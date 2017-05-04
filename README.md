
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
* Extension modules supporting SNMP PDU filtering and on-the-fly modification
* Supports transparent proxy operation (Linux only)
* Works on Linux, Windows and OS X

Download & Install
------------------

SNMP proxy forwarder software is freely available for download from
[PyPI](https://pypi.python.org/pypi/snmpfwd).

Just run:

```bash
$ pip install snmpfwd
```

Alternatively, you can get it from [GitHub](https://github.com/etingof/snmpfwd/releases).

How to use SNMP proxy forwarder
-------------------------------

The system is driven by [configuration files](https://snmpfwd.sourceforge.io/configuration/index.html)
written in a declarative mini-language.

We maintain [a collection](https://snmpfwd.sourceforge.io/configuration/index.html#examples)
of configuration files suited to serve specific use-cases. So you could start
from there. ;-)

Getting help
------------

If something does not work as expected,
[open an issue](https://github.com/etingof/snmpfwd/issues) at GitHub or
post your question [on Stack Overflow](http://stackoverflow.com/questions/ask).

Finally, your PRs are warmly welcome! ;-)

Copyright (c) 2005-2017, [Ilya Etingof](mailto:etingof@gmail.com). All rights reserved.
