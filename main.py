import os
import polyline
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="HerShield Multi-Route Safety Engine API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()

GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")


class RouteRequest(BaseModel):
  origin: str
  destination: str


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

  response = requests.post(url, json=payload, headers=headers)

  if response.status_code != 200:
    raise HTTPException(
        status_code=response.status_code,
        detail=f"Google Maps API Error ({response.status_code}): {response.text}",
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


@app.post("/evaluate-route-safety")
def evaluate_route_safety(request: RouteRequest):
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
