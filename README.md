
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
* SNMPv3 USM supports MD5/SHA/SHA224/SHA256/SHA384/SHA512 auth and
  DES/3DES/AES128/AES192/AES256 privacy crypto algorithms
* Forwards SNMP commands and notifications
* Maintains multiple independent SNMP engines and network transports
* Split client and server parts interconnected through encrypted TCP links
* Flexible SNMP PDU routing
* Extension modules supporting SNMP PDU filtering and on-the-fly modification
* Supports transparent proxy operation (Linux only)
* Works on Linux, Windows and OS X

Download & Install
------------------

SNMP Proxy Forwarder software is freely available for download from
[PyPI](https://pypi.python.org/pypi/snmpfwd).

Just run:

```bash
$ pip install snmpfwd
```

Alternatively, you can get it from [GitHub](https://github.com/etingof/snmpfwd/releases).

How to use SNMP proxy forwarder
-------------------------------

First you need to configure the tool. It is largely driven by
[configuration files](http://snmplabs.com/snmpfwd/configuration/index.html)
written in a declarative mini-language. To help you started, we maintain
[a collection](http://snmplabs.com/snmpfwd/configuration/index.html#examples)
of configuration files designed to serve specific use-cases.

Getting help
------------

If something does not work as expected or we are missing an interesting feature,
[open an issue](https://github.com/etingof/snmpfwd/issues) at GitHub or
post your question [on Stack Overflow](http://stackoverflow.com/questions/ask).

Finally, your PRs are warmly welcome! ;-)

Copyright (c) 2005-2017, [Ilya Etingof](mailto:etingof@gmail.com). All rights reserved.
