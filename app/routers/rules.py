from fastapi import APIRouter, Query
from app.wazuh_client import wazuh
from typing import Optional

router = APIRouter()

@router.get("/")
async def list_rules(
    limit: int = Query(50),
    group: Optional[str] = Query(None, description="Filter by rule group e.g. authentication, syscheck")
):
    """
    Returns Wazuh detection rules.
    Useful for understanding what rules exist and their IDs.
    Helps you know which rule IDs to filter by in alert endpoints.
    """
    params = {"limit": limit}
    if group:
        params["group"] = group
    return await wazuh.get("/rules", params=params)

@router.get("/{rule_id}")
async def get_rule(rule_id: str):
    """
    Returns detail of a specific rule by ID.
    """
    return await wazuh.get(f"/rules/{rule_id}")