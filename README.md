
SNMP Proxy Forwarder
--------------------
[![Downloads](https://img.shields.io/pypi/dm/snmpfwd.svg)](https://pypi.python.org/pypi/snmpfwd)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/etingof/snmpfwd/master/LICENSE.txt)

This tool works as an application-level proxy with a built-in SNMP
message router. It can listen for SNMPv1/v2c/v3 messages on one interface,
parse them to choose their ultimate destinations, and finally send them
out through possibly another interface.

Typical use for an SNMP proxy is to work as an application-level firewall
or a protocol translator that enables SNMPv3 access to a SNMPv1/SNMPv2c
entity or vice versa.

Features
--------

* SNMPv1/v2c/v3 operations with built-in translation capabilities
* Fully configurable, multiple SNMP engines and multiple transports
* Split client and server parts interconnected through encrypted TCP links
* Configurable SNMP message routing
* Extension modules supporting custom processing logic
* Supports transparent proxy operation
* Highly portable across major platforms

Download
--------

SNMP proxy forwarder software is freely available for download from [PyPI](https://pypi.python.org/pypi/snmpfwd).

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
configuration files. See comments and examples inside for more intormation.

Getting help
------------

If something does not work as expected, try browsing
[mailing list archives](https://sourceforge.net/p/snmpsim/mailman/snmpfwd-users/) or post
your question [to Stack Overflow](http://stackoverflow.com/questions/ask).

Feedback and collaboration
--------------------------

I'm interested in bug reports, fixes, suggestions and improvements. Your
pull requests are very welcome!

Copyright (c) 2014-2016, [Ilya Etingof](http://ilya@glas.net). All rights reserved.
