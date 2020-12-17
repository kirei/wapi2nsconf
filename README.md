# Infoblox WAPI to Nameserver

[![Build Status](https://travis-ci.com/kirei/wapi2nsconf.svg?branch=main)](https://travis-ci.com/kirei/wapi2nsconf)

This program creates nameserver configuration files for secondary name servers
based on configuration fetched via [Infoblox](https://www.infoblox.com/) WAPI.

The following nameserver formats are supported:

- [ISC BIND](https://www.isc.org/bind/)
- [NLnet Labs NSD](https://www.nlnetlabs.nl/projects/nsd/)
- [Knot DNS](https://www.knot-dns.cz/)


Development of this software was sponsored by [AddPro AB](https://addpro.se/).


## Templates

The following default configuration templates are provided:

- bind.conf
- knot.conf
- nsd.conf

## Configuration

The configuration file is written in [YAML](https://yaml.org/). Example configuration can be found below.

### WAPI Connection

    wapi:
      endpoint: https://infoblox.example.com/wapi/v2.5
      version: 2.5          # optional (guessed from endpoint URL)
      username: username
      password: password
      check_hostname: True  # default True
      verify: True          # default True
      ca_bundle: ca.pem     # optional

### IPAM Filters

The IPAM filters configures what view to use to find zones. Zones can also be filtered based on name server groups (`ns_groups`) and external attribute (key/value). There's a logic OR between `ns_groups` and `extattr_key`, so a zone is include if it is qualified by any of these options. If the `extattr_value` is configured, the `extattr_key` must have this value. If not specified any value of `extattr_key` is accepted.

    ipam:
      view: default
      ns_groups:
        - "Group1"
        - "Group2"
      extattr_key: "foo"
      extattr_value: "bar"

### DNS Hidden Masters

    masters:
      - ip: 10.0.0.1
        tsig: tsig.example.com

### Configuration File Output

    output:

      - template: knot.conf
        filename: knot.conf
        variables:
          master_base: infoblox
          template_id: infoblox
          storage: /var/lib/knot/zones

      - template: nsd.conf
        filename: nsd.conf
        variables:
          storage_prefix: ""

      - template: bind.conf
        filename: bind.conf
        variables:
          master: infoblox
          storage_prefix: /var/named/infoblox/


## Building

This package uses [Poetry](https://python-poetry.org/) for packaging and dependency management. To build a wheel, use `poetry build`.
