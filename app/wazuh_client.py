import httpx
from datetime import datetime, timedelta
from app.config import settings

class WazuhClient:
    def __init__(self):
        self.base_url = settings.wazuh_base_url
        self.username = settings.wazuh_user
        self.password = settings.wazuh_pass
        self._token = None
        self._token_expiry = None

    async def _ensure_token(self):
        if not self._token or datetime.now() >= self._token_expiry:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.base_url}/security/user/authenticate",
                    auth=(self.username, self.password)
                )
                data = response.json()
                self._token = data["data"]["token"]
                self._token_expiry = datetime.now() + timedelta(minutes=14)
                print(f"[WazuhClient] Token refreshed at {datetime.now()}")

    async def get(self, endpoint: str, params: dict = None):
        await self._ensure_token()
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{self.base_url}{endpoint}",
                headers={"Authorization": f"Bearer {self._token}"},
                params=params
            )
            response.raise_for_status()
            return response.json()

# single shared instance
wazuh = WazuhClient()