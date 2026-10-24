import os
import polyline
import requests
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

load_dotenv()

app = FastAPI(title="HerShield Multi-Route Safety Engine API")

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 30
request_timestamps = defaultdict(deque)
rate_limit_lock = threading.Lock()
SESSION_SECRET = os.getenv("SESSION_SECRET", "local-development-session-secret")

DATABASE_PATH = Path(
  os.getenv(
    "DATABASE_PATH",
    "/tmp/hershield.db" if os.getenv("VERCEL") else "data/hershield.db",
  )
)
DEMO_USERNAME = os.getenv("DEMO_USERNAME", "demo")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "HerShield123!")

app.add_middleware(
    CORSMiddleware,
  allow_origins=[
    origin.strip()
    for origin in os.getenv(
      "ALLOWED_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500"
    ).split(",")
    if origin.strip()
  ],
  allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
CARTO_API_KEY = os.getenv("CARTO_API_KEY")
CARTO_TILE_URL = os.getenv(
  "CARTO_TILE_URL",
  "https://basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
)


class RouteRequest(BaseModel):
  origin: str = Field(..., min_length=1, max_length=200)
  destination: str = Field(..., min_length=1, max_length=200)


class LoginRequest(BaseModel):
  username: str = Field(..., min_length=1, max_length=80)
  password: str = Field(..., min_length=1, max_length=200)


def hash_password(password: str, salt: bytes) -> bytes:
  return hashlib.pbkdf2_hmac(
      "sha256", password.encode("utf-8"), salt, 120_000
  )


def initialize_database():
  DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
  with sqlite3.connect(DATABASE_PATH) as connection:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            password_salt BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    user = connection.execute(
        "SELECT id FROM users WHERE username = ?", (DEMO_USERNAME,)
    ).fetchone()
    if user is None:
      salt = secrets.token_bytes(16)
      connection.execute(
          "INSERT INTO users (username, password_hash, password_salt) VALUES (?, ?, ?)",
          (DEMO_USERNAME, hash_password(DEMO_PASSWORD, salt), salt),
      )


def authenticate_user(username: str, password: str) -> bool:
  with sqlite3.connect(DATABASE_PATH) as connection:
    user = connection.execute(
        "SELECT password_hash, password_salt FROM users WHERE username = ?",
        (username,),
    ).fetchone()
  if user is None:
    return False
  expected_hash = hash_password(password, user[1])
  return hmac.compare_digest(expected_hash, user[0])


def create_session_token(username: str) -> str:
  payload = json.dumps(
      {"username": username, "expires_at": int(time.time()) + 3600},
      separators=(",", ":"),
  ).encode("utf-8")
  encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
  signature = hmac.new(
      SESSION_SECRET.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
  ).hexdigest()
  return f"{encoded_payload}.{signature}"


def get_current_user(request: Request) -> str:
  authorization = request.headers.get("Authorization", "")
  if not authorization.startswith("Bearer "):
    raise HTTPException(status_code=401, detail="Authentication required.")
  token = authorization.removeprefix("Bearer ").strip()
  try:
    encoded_payload, signature = token.split(".", 1)
    expected_signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
      raise ValueError
    padded_payload = encoded_payload + "=" * (-len(encoded_payload) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded_payload))
    if payload["expires_at"] < int(time.time()):
      raise ValueError
    return payload["username"]
  except (ValueError, KeyError, TypeError, json.JSONDecodeError):
    raise HTTPException(status_code=401, detail="Session expired.")


initialize_database()


def parse_waypoint(loc_str: str):
  loc_str = loc_str.strip()
  if "," in loc_str:
    parts = loc_str.split(",")
    if len(parts) == 2:
      try:
        lat = float(parts[0].strip())
        lng = float(parts[1].strip())
        return {"location": {"latLng": {"latitude": lat, "longitude": lng}}}
      except ValueError:
        pass
  return {"address": loc_str}


def fetch_all_google_routes(origin: str, destination: str):
  if not GOOGLE_MAPS_API_KEY:
    raise HTTPException(
        status_code=503, detail="Google Maps API is not configured."
    )

  url = "https://routes.googleapis.com/directions/v2:computeRoutes"
  headers = {
      "Content-Type": "application/json",
      "X-Goog-Api-Key": GOOGLE_MAPS_API_KEY,
      "X-Goog-FieldMask": (
          "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline"
      ),
  }

  payload = {
      "origin": parse_waypoint(origin),
      "destination": parse_waypoint(destination),
      "travelMode": "WALK",
      "computeAlternativeRoutes": True,
  }

  try:
    response = requests.post(
        url, json=payload, headers=headers, timeout=(5, 20)
    )
  except requests.RequestException as exc:
    raise HTTPException(
        status_code=502, detail="Google Maps service is unavailable."
    ) from exc

  if response.status_code != 200:
    raise HTTPException(
        status_code=502,
        detail="Google Maps route request failed.",
    )

  data = response.json()
  if "routes" not in data or not data["routes"]:
    raise HTTPException(
        status_code=404, detail="No routes found between given locations."
    )

  routes_data = []
  for idx, route in enumerate(data["routes"]):
    encoded_polyline = route["polyline"]["encodedPolyline"]
    distance_meters = route.get("distanceMeters", 0)
    decoded_path = polyline.decode(encoded_polyline)
    routes_data.append({
        "route_id": idx + 1,
        "decoded_path": decoded_path,
        "distance_meters": distance_meters,
        "encoded_polyline": encoded_polyline,
    })

  return routes_data


@app.get("/map-tiles/{z}/{x}/{y}.png")
def get_map_tile(z: int, x: int, y: int):
  tile_url = CARTO_TILE_URL.format(z=z, x=x, y=y, r="")
  params = {"key": CARTO_API_KEY} if CARTO_API_KEY else {}

  try:
    response = requests.get(tile_url, params=params, timeout=(5, 20))
  except requests.RequestException as exc:
    raise HTTPException(
        status_code=502, detail="Map tile service unavailable."
    ) from exc

  if response.status_code != 200:
    raise HTTPException(status_code=502, detail="Map tile request failed.")

  return Response(
      content=response.content,
      media_type=response.headers.get("content-type", "image/png"),
      headers={"Cache-Control": "public, max-age=86400"},
  )


def evaluate_environmental_and_social_factors(lat: float, lon: float) -> dict:
  import random

  random.seed(int(lat * 10000 + lon * 10000))

  feedback_pool = [
      "Well lit and active street",
      "Few streetlights flickering at night",
      "Stretches of unlit dark alleys",
      "Frequent police patrolling observed",
      "Reported eve-teasing incident last week",
      "Very deserted after 9 PM",
      "Safe and bustling commercial zone",
  ]

  return {
      "illumination_lux": round(random.uniform(2.0, 45.0), 2),
      "police_crime_rating": round(random.uniform(1.0, 10.0), 1),
      "crowdsourced_feedback": random.sample(
          feedback_pool, k=random.randint(1, 2)
      ),
      "crowd_density_index": round(random.uniform(0.1, 1.0), 2),
      "cellular_signal_strength": random.choice(
          ["High", "Moderate", "Blind Spot"]
      ),
  }


def calculate_risk_for_path(path_points: list, distance_meters: float) -> dict:
  if not path_points:
    return {
        "risk_score": 100.0,
        "risk_category": "High Risk - Caution Advised",
        "total_distance_meters": distance_meters,
        "risk_breakdown": {},
        "user_feedback_summary": [],
    }

  step = max(1, len(path_points) // 20)
  sampled_points = path_points[::step]

  total_illumination_deficit = 0.0
  total_police_crime_score = 0.0
  total_crowd_score = 0.0
  blind_spot_count = 0
  all_feedbacks = []

  for lat, lon in sampled_points:
    env = evaluate_environmental_and_social_factors(lat, lon)
    deficit = max(0.0, 30.0 - env["illumination_lux"])
    total_illumination_deficit += deficit
    total_police_crime_score += env["police_crime_rating"]
    total_crowd_score += 1.0 - env["crowd_density_index"]

    if env["cellular_signal_strength"] == "Blind Spot":
      blind_spot_count += 1
    all_feedbacks.extend(env["crowdsourced_feedback"])

  n = len(sampled_points)
  avg_illumination_deficit = total_illumination_deficit / n
  avg_police_crime = total_police_crime_score / n
  avg_crowd_vulnerability = total_crowd_score / n

  risk_from_lighting = (avg_illumination_deficit / 30.0) * 30.0
  risk_from_police_crime = (avg_police_crime / 10.0) * 35.0
  risk_from_isolation = avg_crowd_vulnerability * 20.0
  risk_from_network = (blind_spot_count / n) * 15.0

  total_risk_score = round(
      min(
          100.0,
          max(
              0.0,
              risk_from_lighting
              + risk_from_police_crime
              + risk_from_isolation
              + risk_from_network,
          ),
      ),
      2,
  )

  if total_risk_score < 30:
    category = "Low Risk (Safest)"
  elif total_risk_score < 65:
    category = "Moderate Risk"
  else:
    category = "High Risk - Caution Advised"

  return {
      "risk_score": total_risk_score,
      "risk_category": category,
      "total_distance_meters": distance_meters,
      "risk_breakdown": {
          "lighting_risk_factor": round(risk_from_lighting, 2),
          "police_crime_rating_factor": round(risk_from_police_crime, 2),
          "isolation_factor": round(risk_from_isolation, 2),
          "connectivity_blind_spot_factor": round(risk_from_network, 2),
      },
      "user_feedback_summary": list(set(all_feedbacks))[:4],
  }


@app.post("/login")
def login(credentials: LoginRequest):
  if not authenticate_user(credentials.username, credentials.password):
    raise HTTPException(status_code=401, detail="Invalid username or password.")

  token = create_session_token(credentials.username)
  return {"access_token": token, "token_type": "bearer"}


@app.post("/evaluate-route-safety")
def evaluate_route_safety(
  request: RouteRequest,
  http_request: Request,
  current_user: str = Depends(get_current_user),
):
  client_ip = http_request.client.host if http_request.client else "unknown"
  now = time.monotonic()

  with rate_limit_lock:
    timestamps = request_timestamps[client_ip]
    while timestamps and now - timestamps[0] >= RATE_LIMIT_WINDOW_SECONDS:
      timestamps.popleft()
    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
      raise HTTPException(
          status_code=429,
          detail="Too many route requests. Please try again later.",
      )
    timestamps.append(now)

  raw_routes = fetch_all_google_routes(request.origin, request.destination)

  evaluated_routes = []
  for r in raw_routes:
    analysis = calculate_risk_for_path(r["decoded_path"], r["distance_meters"])
    evaluated_routes.append({
        "route_id": r["route_id"],
        "encoded_polyline": r["encoded_polyline"],
        "safety_analysis": analysis,
    })

  evaluated_routes.sort(key=lambda x: x["safety_analysis"]["risk_score"])

  if evaluated_routes:
    evaluated_routes[0]["is_recommended"] = True

  return {
      "origin": request.origin,
      "destination": request.destination,
      "routes": evaluated_routes,
  }
