"""WAPI Classes"""

import logging
from dataclasses import dataclass
from typing import Any, Self

import httpx

logger = logging.getLogger(__name__)

MAX_RESULTS = 1000


@dataclass(frozen=True)
class InfobloxZone:
    fqdn: str
    disabled: bool
    extattrs: dict
    view: str
    ns_group: str | None = None
    description: str | None = None

    @classmethod
    def from_wapi(cls, wzone: dict[str, Any], view: str) -> Self | None:
        valid = False
        if wzone["zone_format"] == "IPV4" or wzone["zone_format"] == "IPV6":
            fqdn = wzone["display_domain"]
            description = wzone["dns_fqdn"]
            valid = True
        elif wzone["zone_format"] == "FORWARD":
            fqdn = wzone["dns_fqdn"]
            description = wzone["display_domain"]
            valid = True
        else:
            valid = False

        if not valid:
            logger.warning("Invalid zone: %s", wzone)
            return None

        return cls(
            fqdn=fqdn,
            ns_group=wzone.get("ns_group"),
            disabled=wzone.get("disabled", False),
            extattrs=wzone.get("extattrs", {}),
            description=description,
            view=view,
        )


class WAPI:
    """WAPI Client"""

    def __init__(
        self,
        session: httpx.Client,
        endpoint: str,
        version: float | None = None,
        max_results: int = MAX_RESULTS,
    ):
        self.session = session
        self.endpoint = endpoint
        self.version = version
        self.max_results = max_results

    def zones(self, view: str) -> list[InfobloxZone]:
        """Fetch all zones via WAPI"""

        fields = [
            "dns_fqdn",
            "fqdn",
            "disable",
            "display_domain",
            "zone_format",
            "ns_group",
        ]

        if self.version is not None and self.version >= 1.2:
            fields.append("extattrs")

        params = {
            "view": view,
            "_return_fields": ",".join(fields),
            "_return_type": "json",
            "_return_as_object": 1,
            "_paging": "1",
            "_max_results": self.max_results,
        }

        logger.info("Fetching zones from %s", self.endpoint)
        zones: list[InfobloxZone] = []
        page_no = 0

        while True:
            response = self.session.get(f"{self.endpoint}/zone_auth", params=params)
            response.raise_for_status()

            res = response.json()
            page_no += 1

            logger.debug("Received %d zones in page %d", len(res["result"]), page_no)

            for wzone in res["result"]:
                z = InfobloxZone.from_wapi(wzone=wzone, view=view)
                if z:
                    zones.append(z)

            if not (next_page_id := res.get("next_page_id")):
                break

            params["_page_id"] = next_page_id

        logger.debug("Received a total of %d zones", len(zones))

        return sorted(zones, key=lambda x: x.fqdn)
