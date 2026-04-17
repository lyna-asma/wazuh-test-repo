# auth.py
import httpx
from app.config import WAZUH_API_URL, WAZUH_USERNAME, WAZUH_PASSWORD

async def get_wazuh_token() -> str:
    """Login to Wazuh API and return the token."""
    auth_url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(
            auth_url,
            auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
            timeout=30.0
        )
        response.raise_for_status()
        return response.text  # token as plain text