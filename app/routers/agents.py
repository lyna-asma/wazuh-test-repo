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
    """
    Returns detail of a single agent by ID or name.
    This is the data source for the Agent Details page (F13).
    """
    # If agent_id contains any non-digit, assume it's a name and resolve to ID
    if not agent_id.isdigit():
        # Query Wazuh to get agent by name
        name_response = await wazuh.get(f"/agents/name/{agent_id}")
        # Extract the numeric ID from the response
        numeric_id = name_response["data"]["affected_items"][0]["id"]
        return await wazuh.get(f"/agents/{numeric_id}")
    # Otherwise, it's already a numeric ID
    return await wazuh.get(f"/agents/{agent_id}")

@router.get("/{agent_id}/key")
async def get_agent_key(agent_id: str):
    """
    Returns the agent registration key.
    Useful for understanding agent enrollment.
    """
    return await wazuh.get(f"/agents/{agent_id}/key")