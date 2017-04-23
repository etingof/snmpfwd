
SNMP Proxy Forwarder
--------------------

[![PyPI](https://img.shields.io/pypi/v/snmpfwd.svg?maxAge=2592000)](https://pypi.python.org/pypi/snmpfwd)
[![Python Versions](https://img.shields.io/pypi/pyversions/snmpfwd.svg)](https://pypi.python.org/pypi/snmpfwd/)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/etingof/snmpfwd/master/LICENSE.txt)

The SNMP Proxy Forwarder tool works as an application-level proxy with a built-in
SNMP message router. SNMP forwarder design features split client/server operation
that promotes having one part of the system in DMZ while other part is 
facing the Internet. Message routing can be programmed via a declarative
mini-language.

Typical use case for an SNMP proxy is to work as an application-level firewall
or a protocol translator that enables SNMPv3 access to a SNMPv1/SNMPv2c
entity or vice versa.

Features
--------

* SNMPv1/v2c/v3 operations with built-in protocol and transport translation capabilities
* Fully configurable, multiple SNMP engines and multiple transports
* Split client and server parts interconnected through encrypted TCP links
* Configurable SNMP message routing
* Extension modules supporting SNMP messages introspection and modification
* Supports transparent proxy operation (Linux only)
* Works on Linux, Windows and OS X

Download
--------

SNMP proxy forwarder software is freely available for download from
[PyPI](https://pypi.python.org/pypi/snmpfwd).

Installation
------------

Just run:

```bash
$ pip install snmpfwd
```

How to use SNMP proxy forwarder
-------------------------------

Once installed, configure both client and server part of the tool by tackling
[client.conf](https://raw.githubusercontent.com/etingof/snmpfwd/master/conf/client.conf) and
[server.conf](https://raw.githubusercontent.com/etingof/snmpfwd/master/conf/server.conf)
configuration files.

Comprehensive configuration language reference could be found at
the [project site](http://snmpfwd.sf.net).

Getting help
------------

If something does not work as expected,
[open an issue](https://github.com/etingof/snmpfwd/issues) at GitHub or
post your question [on Stack Overflow](http://stackoverflow.com/questions/ask).

Finally, your PRs are warmly welcome! ;-)

Copyright (c) 2005-2017, [Ilya Etingof](mailto:etingof@gmail.com). All rights reserved.
