"""Configuration schema"""

import ipaddress

import voluptuous as vol
import voluptuous.humanize
from voluptuous.schema_builder import message


class IPInvalid(vol.Invalid):
    """The value is not valid IP."""


@message("expected an IP address", cls=IPInvalid)
def IPAddress(v):
    try:
        if not v:
            raise IPInvalid("expected an IP address")
        ipaddress.ip_address(v)
        return v
    except:
        raise ValueError


CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required("wapi"): vol.Schema(
            {
                vol.Required("endpoint"): vol.FqdnUrl,
                "version": float,
                vol.Required("username"): str,
                vol.Required("password"): str,
                "ca_bundle": vol.IsFile,
                vol.Required("check_hostname"): bool,
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
            vol.Schema({vol.Required("ip"): IPAddress, vol.Required("tsig"): str})
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


def validate_config(conf: dict):
    return voluptuous.humanize.validate_with_humanized_errors(conf, CONFIG_SCHEMA)
