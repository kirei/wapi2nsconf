# Infoblox WAPI to Nameserver

[![Build Status](https://travis-ci.com/kirei/wapi2nsconf.svg?branch=main)](https://travis-ci.com/kirei/wapi2nsconf)

This program creates nameserver configuration files for secondary name servers
based on configuration fetched via [Infoblox](https://www.infoblox.com/) WAPI.

The following nameserver formats are supported:

- [ISC BIND](https://www.isc.org/bind/)
- [NLnet Labs NSD](https://www.nlnetlabs.nl/projects/nsd/)
- [Knot DNS](https://www.knot-dns.cz/)


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
     version: 2.5
     username: username
     password: password
     check_hostname: True

### IPAM Filters

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
