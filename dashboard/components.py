from __future__ import annotations


def incident_card(incident: dict) -> dict:
    return {"title": incident.get("summary", "Incident"), "details": incident}