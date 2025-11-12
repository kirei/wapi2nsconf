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

import jinja2
import yaml

from .config import Configuration, IpamConfiguration
from .utils import function_to_json
from .wapi import WAPI, InfobloxZone

logger = logging.getLogger(__name__)

PACKAGE_NAME = "wapi2nsconf"
DEFAULT_CONF_FILENAME = "wapi2nsconf.yaml"
DEFAULT_TEMPLATES_PATH = "templates/"


def filter_zones(
    zones: list[InfobloxZone], ipam_conf: IpamConfiguration
) -> list[InfobloxZone]:
    res = []

    for zone in zones:
        if zone.disabled:
            continue

        if ipam_conf.ns_groups is None:
            logger.debug("%s included by default", zone.fqdn)
            res.append(zone)
            continue
        elif zone.ns_group in ipam_conf.ns_groups:
            logger.debug("%s included by ns_group", zone.fqdn)
            res.append(zone)
            continue
        elif ipam_conf.extattr_key is not None:
            zone_val = zone.extattrs.get(ipam_conf.extattr_key, {}).get("value")
            if ipam_conf.extattr_value is not None:
                if zone_val == ipam_conf.extattr_value:
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
            elif zone.extattrs.get(ipam_conf.extattr_key, None) is not None:
                logger.debug("%s included by extended attribute key", zone.fqdn)
                res.append(zone)
                continue

        logger.debug("Skipping %s", zone.fqdn)

    return res


def output_nsconf(
    zones: list[InfobloxZone],
    conf: Configuration,
    templates_path: str | None = None,
) -> None:
    loader: jinja2.BaseLoader

    if templates_path is not None:
        logger.debug("Using templates in %s", templates_path)
        loader = jinja2.FileSystemLoader(templates_path)
    else:
        logger.debug("Using package templates")
        loader = jinja2.PackageLoader(PACKAGE_NAME, "templates")

    env = jinja2.Environment(loader=loader)
    env.filters["to_json"] = function_to_json

    for output in conf.output:
        template = env.get_template(output.template, globals=output.variables)
        masters = [
            {"ip": str(master.ip), "tsig": master.tsig} for master in conf.masters
        ]
        res = template.render(zones=zones, masters=masters)

        output_filename = output.filename
        with open(output_filename, "w") as fp:
            fp.write(res)
        logger.info("Output written to %s", output_filename)


def main() -> None:
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
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO)

    try:
        with open(args.conf_filename) as fp:
            conf = Configuration.model_validate(yaml.safe_load(fp))
    except FileNotFoundError:
        parser.print_help()
        sys.exit(0)

    if args.check_config:
        sys.exit(0)

    wapi = WAPI(
        session=conf.wapi.get_httpx_client(),
        endpoint=str(conf.wapi.endpoint),
        version=conf.wapi.get_wapi_version(),
        max_results=conf.wapi.max_results,
    )

    views = conf.ipam.views or [conf.ipam.view]

    all_zones: list[InfobloxZone] = []
    for view in views:
        logger.debug("Fetching zones for view %s", view)
        all_zones.extend(wapi.zones(view=view))

    our_zones = filter_zones(zones=all_zones, ipam_conf=conf.ipam)

    output_nsconf(zones=our_zones, conf=conf, templates_path=args.templates)


if __name__ == "__main__":
    main()
