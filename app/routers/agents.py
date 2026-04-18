from fastapi import APIRouter, Query
from app.wazuh_client import wazuh
from typing import Optional

router = APIRouter()

@router.get("/")
async def list_agents(
    status: Optional[str] = Query(None, description="Filter by status: active, disconnected"),
    limit: int = Query(50, description="Number of agents to return")
):
    """
    Returns all registered Wazuh agents with status, OS, IP, last keep-alive.
    This is the data source for the Agent Monitoring page (F4).
    """
    params = {"limit": limit}
    if status:
        params["status"] = status
    return await wazuh.get("/agents", params=params)

@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    return await wazuh.get("/agents", params={"agents_list": agent_id})

@router.get("/{agent_id}/key")
async def get_agent_key(agent_id: str):
    """
    Returns the agent registration key.
    Useful for understanding agent enrollment.
    """
    return await wazuh.get(f"/agents/{agent_id}/key")