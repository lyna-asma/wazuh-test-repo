from fastapi import APIRouter, Query
from app.wazuh_client import wazuh
from typing import Optional

router = APIRouter()

@router.get("/")
async def list_alerts(
    limit: int = Query(50, description="Number of alerts to return"),
    level: Optional[int] = Query(None, description="Minimum severity level 1-15"),
    agent_name: Optional[str] = Query(None, description="Filter by agent name"),
    q: Optional[str] = Query(None, description="Raw Wazuh query string e.g. rule.groups=authentication")
):
    """
    Returns security alerts from Wazuh.
    This is the core data source for F2 (Alerts Console),
    F6 (Auth Events), F7 (Firewall Events), F14 (FIM Events).
    Without real agents sending logs this may return empty or minimal data.
    """
    params = {
        "limit": limit,
        "sort": "-timestamp"
    }
    if level:
        params["level"] = level
    if agent_name:
        params["q"] = f"agent.name={agent_name}"
    if q:
        params["q"] = q
    return await wazuh.get("/alerts", params=params)

@router.get("/auth")
async def get_auth_events(
    limit: int = Query(50)
):
    """
    Returns authentication-related alerts only.
    Filters by rule group 'authentication'.
    Data source for F6 (Authentication Events page).
    Requires Windows agents with Security log collection configured.
    """
    return await wazuh.get("/alerts", params={
        "q": "rule.groups=authentication",
        "limit": limit,
        "sort": "-timestamp"
    })

@router.get("/firewall")
async def get_firewall_events(
    limit: int = Query(50)
):
    """
    Returns OPNsense firewall events.
    Requires OPNsense syslog forwarding to Wazuh configured.
    Data source for F7 (Firewall Events page).
    Will return empty without OPNsense in the topology.
    """
    return await wazuh.get("/alerts", params={
        "q": "agent.name=OPNsense",
        "limit": limit,
        "sort": "-timestamp"
    })

@router.get("/fim")
async def get_fim_events(
    limit: int = Query(50)
):
    """
    Returns File Integrity Monitoring events.
    Filters by rule group 'syscheck'.
    Data source for F14 (FIM Events page).
    Requires agents with syscheck module enabled.
    """
    return await wazuh.get("/alerts", params={
        "q": "rule.groups=syscheck",
        "limit": limit,
        "sort": "-timestamp"
    })

@router.get("/overview")
async def get_alerts_overview():
    """
    Returns alert statistics per agent.
    Data source for F3 (Dashboard Overview) charts.
    """
    return await wazuh.get("/overview/agents")