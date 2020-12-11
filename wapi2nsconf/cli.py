#!/usr/bin/env python3

"""
Build nameserver configurations using Infoblox WAPI


Copyright (c) 2020 Kirei AB. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import argparse
import logging
import sys
import warnings
from typing import List, Optional

import jinja2
import requests
import urllib3
import yaml
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

from .config import validate_config
from .wapi import WAPI, InfobloxZone

logger = logging.getLogger(__name__)

PACKAGE_NAME = "wapi2nsconf"
DEFAULT_CONF_FILENAME = "wapi2nsconf.yaml"
DEFAULT_TEMPLATES_PATH = "templates/"
DEFAULT_VIEW = "default"


class HostNameIgnoringAdapter(HTTPAdapter):
    """Never check any hostnames"""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, assert_hostname=False
        )


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


def output_nsconf(
    zones: List[InfobloxZone], conf: dict, templates_path: Optional[str] = None
) -> None:

    if templates_path is not None:
        logger.debug("Using templates in %s", templates_path)
        loader = jinja2.FileSystemLoader(templates_path)
    else:
        logger.debug("Using package templates")
        loader = jinja2.PackageLoader(PACKAGE_NAME, "templates")
    env = jinja2.Environment(loader=loader)

    for output in conf.get("output", []):

        template = env.get_template(
            output["template"], globals=output.get("variables", {})
        )
        res = template.render(zones=zones, masters=conf.get("masters", []))

        output_filename = output["filename"]
        with open(output_filename, "wt") as output_file:
            output_file.write(res)
        logger.info("Output written to %s", output_filename)


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
        "--templates",
        dest="templates",
        metavar="path",
        help="Templates path",
        required=False,
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

    validate_config()
    if args.check_config:
        sys.exit(0)

    wapi_conf = conf["wapi"]
    ipam_conf = conf.get("ipam", {})

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

    all_zones = wapi.zones(view=ipam_conf.get("view", DEFAULT_VIEW))
    our_zones = filter_zones(zones=all_zones, conf=ipam_conf)
    output_nsconf(zones=our_zones, conf=conf, templates_path=args.templates)


if __name__ == "__main__":
    main()
