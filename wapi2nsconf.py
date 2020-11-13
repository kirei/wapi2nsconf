#!/usr/bin/env python3

"""Build nameserver configurations using Infoblox WAPI"""

import argparse
import logging
import os
import sys
import warnings
from dataclasses import dataclass
from typing import List, Optional

import requests
import urllib3
import voluptuous as vol
import voluptuous.humanize
import yaml
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

logger = logging.getLogger(__name__)

DEFAULT_CONF_FILENAME = "wapi2nsconf.yaml"
DEFAULT_MASTER = "infoblox"
DEFAULT_TEMPLATE = "infoblox"

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
        vol.Required("view"): str,
        "ns_groups": [str],
        "extattr_key": str,
        "extattr_value": str,
        vol.Required("masters"): [
            vol.Schema({vol.Required("ip"): vol.FqdnUrl, vol.Required("tsig"): str})
        ],
        vol.Required("output"): vol.Schema(
            {
                "bind": vol.Schema(
                    {
                        vol.Required("filename"): str,
                        "master": str,
                        "path": str,
                    }
                ),
                "nsd": vol.Schema(
                    {
                        vol.Required("filename"): str,
                    }
                ),
                "knot": vol.Schema(
                    {
                        vol.Required("filename"): str,
                        "master": str,
                        "template": str,
                        "storage": str,
                    }
                ),
            }
        ),
    }
)


class HostNameIgnoringAdapter(HTTPAdapter):
    """Never check any hostnames"""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, assert_hostname=False
        )


class NoAliasDumper(yaml.Dumper):
    def ignore_aliases(self, data):
        return True


@dataclass(frozen=True)
class InfobloxZone(object):
    fqdn: str
    disabled: bool
    extattrs: dict
    ns_group: Optional[str] = None
    description: Optional[str] = None

    @classmethod
    def from_wapi(cls, wzone: dict):
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

    def __init__(self, session: requests.Session, endpoint: str, version=None):
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


def filter_zones(zones: List[InfobloxZone], conf: dict) -> List[InfobloxZone]:

    res = []
    ns_groups = conf.get("ns_groups", None)

    extattr_key = conf.get("extattr_key")
    extattr_val = conf.get("extattr_value")

    for zone in zones:

        if zone.disabled:
            continue

        if ns_groups is None:
            logger.debug("%s included by default", zone.fqdn)
            res.append(zone)
            continue
        elif zone.ns_group in ns_groups:
            logger.debug("%s included by ns_group", zone.fqdn)
            res.append(zone)
            continue
        elif extattr_key is not None:
            zone_val = zone.extattrs.get(extattr_key, {}).get("value")
            if extattr_val is not None:
                if zone_val == extattr_val:
                    logger.debug(
                        "%s included by extended attribute key/value", zone.fqdn
                    )
                    res.append(zone)
                    continue
                else:
                    logger.debug(
                        "%s skipped by extended attribute key/value", zone.fqdn
                    )
                    continue
            elif zone.extattrs.get(extattr_key, None) is not None:
                logger.debug("%s included by extended attribute key", zone.fqdn)
                res.append(zone)
                continue

        logger.debug("Skipping %s", zone.fqdn)

    return res


def output_nsconf(zones: List[InfobloxZone], conf: dict):

    bind_output = conf["output"].get("bind")
    if bind_output:
        master = bind_output.get("master", "infoblox")
        path = bind_output.get("path", "")

        output_file = open(bind_output["filename"], "wt")
        original_stdout = sys.stdout
        sys.stdout = output_file

        print(f"masters {master} {{")
        for m in conf.get("masters", []):
            print(f"    {m['ip']} key {m['tsig']};")
        print("}")
        print("")

        for zone in zones:
            zfilename = os.path.join(path, zone.fqdn)
            print(f"# {zone.description}")
            print(f'zone "{zone.fqdn}" {{')
            print(f"    type slave;")
            print(f'    file "{zfilename}";')
            print(f"    masters {{ {master}; }};")
            print(f"}};")
            print("")

        sys.stdout = original_stdout
        output_file.close()

    nsd_output = conf["output"].get("nsd")
    if nsd_output:
        master = nsd_output.get("master", DEFAULT_MASTER)
        path = nsd_output.get("path", "")

        output_file = open(nsd_output["filename"], "wt")
        original_stdout = sys.stdout
        sys.stdout = output_file

        for zone in zones:
            zfilename = os.path.join(path, zone.fqdn)
            print(f"# {zone.description}")
            print(f"zone:")
            print(f"    name: {zone.fqdn}")
            print(f"    zonefile: {zfilename}")
            for m in conf.get("masters", []):
                print(f"    request-ixfr: {m['ip']} {m['tsig']}")
                print(f"    allow-notify: {m['ip']} {m['tsig']}")
            print("")

        sys.stdout = original_stdout
        output_file.close()

    knot_output = conf["output"].get("knot")
    if knot_output:
        knot_config = {}
        master_base = knot_output.get("master", DEFAULT_MASTER)
        template_name = knot_output.get("template", DEFAULT_TEMPLATE)
        masters = []
        count = 0

        knot_config["remote"] = []
        for m in conf.get("masters", []):
            count += 1
            masters.append(f"{master_base}_{count}")
            knot_config["remote"].append(
                {"id": masters[-1], "address": m["ip"], "key": m["tsig"]}
            )

        template = {"id": template_name, "master": masters}
        if "storage" in knot_output:
            template["storage"] = knot_output["storage"]

        knot_config["template"] = template

        knot_config["zone"] = []
        for zone in zones:
            knot_config["zone"].append({"domain": zone.fqdn, "template": template_name})

        with open(knot_output["filename"], "wt") as output_file:
            output_file.write(yaml.dump(knot_config, Dumper=NoAliasDumper))


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="wapi2nsconf")
    parser.add_argument(
        "--conf",
        dest="conf_filename",
        default=DEFAULT_CONF_FILENAME,
        metavar="filename",
        help="configuration file",
        required=False,
    )
    parser.add_argument(
        "--check",
        dest="check_config",
        action="store_true",
        help="Check configuration only",
    )
    parser.add_argument(
        "--debug", dest="debug", action="store_true", help="Print debug information"
    )
    parser.add_argument(
        "--silent", dest="silent", action="store_true", help="Silent operation"
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.silent:
        warnings.filterwarnings(
            "ignore", category=urllib3.exceptions.SubjectAltNameWarning
        )
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("requests").setLevel(logging.INFO)

    try:
        conf = yaml.safe_load(open(args.conf_filename, "rt"))
    except FileNotFoundError:
        parser.print_help()
        sys.exit(0)

    voluptuous.humanize.validate_with_humanized_errors(conf, CONFIG_SCHEMA)
    if args.check_config:
        sys.exit(0)

    wapi_conf = conf["wapi"]

    session = requests.Session()
    session.verify = wapi_conf.get("ca_bundle")
    if not wapi_conf.get("check_hostname", True):
        session.mount("https://", HostNameIgnoringAdapter())
    session.auth = (wapi_conf["username"], wapi_conf["password"])
    wapi = WAPI(
        session=session,
        endpoint=wapi_conf["endpoint"],
        version=wapi_conf.get("version"),
    )

    wapi_zones = wapi.zones(view=conf["view"])
    zones = filter_zones(wapi_zones, conf)
    output_nsconf(zones, conf)


if __name__ == "__main__":
    main()
