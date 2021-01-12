"""Configuration schema"""

import ipaddress

import voluptuous as vol
import voluptuous.humanize
from voluptuous.validators import DOMAIN_REGEX

IP_ADDRESS = ipaddress.ip_address
DOMAIN_NAME = vol.Any(vol.Match(r"\w+"), vol.Match(DOMAIN_REGEX))

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required("wapi"): vol.Schema(
            {
                vol.Required("endpoint"): vol.FqdnUrl,
                "version": float,
                vol.Required("username"): str,
                vol.Required("password"): str,
                "ca_bundle": vol.IsFile,
                "check_hostname": bool,
                "verify": bool,
            }
        ),
        "ipam": vol.Schema(
            {
                "view": str,
                "ns_groups": [str],
                "extattr_key": str,
                "extattr_value": str,
            }
        ),
        vol.Required("masters"): [
            vol.Schema(
                {vol.Required("ip"): IP_ADDRESS, vol.Required("tsig"): DOMAIN_NAME}
            )
        ],
        vol.Required("output"): [
            vol.Schema(
                {
                    vol.Required("template"): vol.IsFile,
                    vol.Required("filename"): str,
                    "variables": dict,
                }
            )
        ],
    }
)


def validate_config(conf: dict) -> None:
    voluptuous.humanize.validate_with_humanized_errors(conf, CONFIG_SCHEMA)
