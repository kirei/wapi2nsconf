"""WAPI Classes"""

import logging
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InfobloxZone(object):
    fqdn: str
    disabled: bool
    extattrs: dict
    ns_group: Optional[str] = None
    description: Optional[str] = None

    @classmethod
    def from_wapi(cls, wzone: dict) -> Optional["InfobloxZone"]:
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
        )


class WAPI(object):
    """WAPI Client"""

    def __init__(
        self, session: requests.Session, endpoint: str, version: Optional[float] = None
    ):
        self.session = session
        self.endpoint = endpoint
        self.version = version

    def zones(self, view: str) -> List[InfobloxZone]:
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
        }

        logger.info("Fetching zones from %s", self.endpoint)
        response = self.session.get(f"{self.endpoint}/zone_auth", params=params)

        response.raise_for_status()

        res = []
        for wzone in response.json():
            z = InfobloxZone.from_wapi(wzone)
            if z:
                res.append(z)

        return sorted(res, key=lambda x: x.fqdn)
