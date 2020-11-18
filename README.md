# Infoblox WAPI to Nameserver

This program creates nameserver configuration files for secondary name servers
based on configuration fetched via [Infoblox](https://www.infoblox.com/) WAPI.

The following nameserver formats are supported:

- [ISC BIND](https://www.isc.org/bind/)
- [NLnet Labs NSD](https://www.nlnetlabs.nl/projects/nsd/)
- [Knot DNS](https://www.knot-dns.cz/)

## Building

This package uses [Poetry](https://python-poetry.org/) for packaging and dependency management. To build a wheel, use `poetry build`.
