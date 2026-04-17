from fastapi import FastAPI
from app.routers import agents, alerts, manager, rules

app = FastAPI(
    title="Mini SIEM — Wazuh API Test",
    description="""
    Test repository for validating Wazuh API connectivity and responses.
    All endpoints proxy directly to Wazuh REST API on the local VMware VM.
    Use this to understand data structures before building the full dashboard.
    """,
    version="0.1.0"
)

app.include_router(manager.router, prefix="/api/manager", tags=["Manager"])
app.include_router(agents.router,  prefix="/api/agents",  tags=["Agents"])
app.include_router(alerts.router,  prefix="/api/alerts",  tags=["Alerts"])
app.include_router(rules.router,   prefix="/api/rules",   tags=["Rules"])

@app.get("/")
async def root():
    return {
        "message": "Wazuh API test server running",
        "docs": "/docs",
        "wazuh_endpoints_tested": [
            "GET /api/manager/status",
            "GET /api/manager/info",
            "GET /api/agents/",
            "GET /api/agents/{id}",
            "GET /api/alerts/",
            "GET /api/alerts/auth",
            "GET /api/alerts/firewall",
            "GET /api/alerts/fim",
            "GET /api/alerts/overview",
            "GET /api/rules/",
        ]
    }