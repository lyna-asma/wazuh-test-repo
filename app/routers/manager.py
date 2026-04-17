from fastapi import APIRouter
from app.wazuh_client import wazuh

router = APIRouter()

@router.get("/status")
async def get_manager_status():
    """
    Returns Wazuh manager daemon status and version info.
    Tests basic connectivity and token authentication.
    """
    return await wazuh.get("/manager/status")

@router.get("/info")
async def get_manager_info():
    """
    Returns Wazuh manager version, installation path, and config.
    """
    return await wazuh.get("/manager/info")