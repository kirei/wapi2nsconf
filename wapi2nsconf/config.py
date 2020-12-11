"""Configuration schema"""

import voluptuous as vol
import voluptuous.humanize

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
            vol.Schema({vol.Required("ip"): vol.FqdnUrl, vol.Required("tsig"): str})
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
