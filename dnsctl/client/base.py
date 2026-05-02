import httpx

from ..exceptions import TechnitiumAPIError, TechnitiumInvalidToken, TechnitiumUnavailable


class TechnitiumClient:
    def __init__(self, base_url: str, token: str, http_client: httpx.AsyncClient):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._http = http_client

    async def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"{self.base_url}/api/{endpoint}"
        params = kwargs.pop("params", {})
        params["token"] = self.token
        try:
            resp = await self._http.request(method, url, params=params, **kwargs)
            resp.raise_for_status()
        except httpx.ConnectError as e:
            raise TechnitiumUnavailable(str(e)) from e
        except httpx.TimeoutException as e:
            raise TechnitiumUnavailable(str(e)) from e

        data = resp.json()
        status = data.get("status")
        if status == "invalid-token":
            raise TechnitiumInvalidToken()
        if status == "error":
            raise TechnitiumAPIError(data.get("errorMessage", "Unknown error"))

        return data.get("response", data)

    async def check_connection(self) -> tuple[bool, str]:
        try:
            await self._request("GET", "zones/list")
            return True, "Connected"
        except TechnitiumUnavailable as e:
            return False, f"Cannot reach server: {e}"
        except TechnitiumInvalidToken:
            return False, "Invalid API token"
        except TechnitiumAPIError as e:
            return False, f"API error: {e.message}"
