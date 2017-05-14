
SNMP Proxy Forwarder
====================

The SNMP Proxy Forwarder tool is a standards-compliant, flexible,
multiprotocol SNMP proxy implementation.

Key features:

* Complete SNMPv1/v2c/v3 support with built-in protocol and transport
  translation capabilities
* Forwards SNMP commands and notifications
* Maintains multiple independent SNMP engines and network transports
* Split client and server parts
* Configurable SNMP PDU routing policy
* Extension modules supporting SNMP PDU filtering and on-the-fly modification
* Supports transparent proxy operation (Linux only)
* Works on Linux, Windows and OS X

Architecture
------------

The otherwise monolithic SNMP proxy is split onto two parts: server and client.
For SNMP commands, server part
acts as `SNMP agent <https://tools.ietf.org/html/rfc3411#section-3.1.3.2>`_
while the client part is `SNMP manager <https://tools.ietf.org/html/rfc3411#section-3.1.3.1>`_.
For SNMP notifications server and client roles are reversed.
The server and client parts maintain persistent, authenticated and encrypted
connections with each other for the purpose of passing SNMP messages back
and forth.

Server and client parts may reside at different networks thus improving
security and network isolation.

Depending on the network topology and goals one could run multiple instances
of server and/or client parts of the system. Servers and clients may thus
build a network of server/client nodes passing SNMP messages to each other
achieving better reliability, performance and security.

Both server and client parts can be configured to route SNMP messages
based on virtually any SNMP message property. For instance, server part
may chose to route SNMP messages to clients residing at different networks
depending on specific OID being present in the message. Or client part can
chose SNMP agent to forward SNMP message to depending on the original
destination address at which server part received SNMP message in the
first place.

Besides SNMP message routing, both server and client parts can modify
SNMP PDU messages before passing them on. Changes may apply to both incoming
and outgoing SNMP PDU messages. The logic powering SNMP message modification
can be expressed in form of isolated `Python <http://www.python.org>`_
snippets called :ref:`plugins <plugins>`. Users can implement their own
plugins and let SNMP Proxy Forwarder calling them.

Configuration
-------------

The system is driven by configuration files. Depending on the desired system's
configuration, the complexity of configuration files can vary. We maintain a
collection of use-cases and example configurations implementing them.

.. toctree::
   :maxdepth: 2

   /configuration/index

Installation
------------

The easiest way to download and install SNMP Proxy Forwarder is via Python `pip` tool:

.. code-block:: bash

   # pip install snmpfwd

Alternatively, you can download the Python package from
`GitHub repo <https://github.com/etingof/snmpfwd/releases>`_ and install is manually.

The tool requires Python 2.4 to 2.7 or 3.1 onwards.

Source code
-----------

SNMP Proxy Forwarder is a free and open source tool. It is distributed under highly
permissive :doc:`2-clause BSD license </license>`. You can fork or download source code from
`GitHub <https://github.com/etingof/snmpfwd>`_.

Detailed list of new features and fixes could be read in the :doc:`changelog </changelog>`.

Contact
-------

If something does not work as expected,
`open an issue <https://github.com/etingof/snmpfwd/issues>`_
at GitHub or post your question
`on Stack Overflow <http://stackoverflow.com/questions/ask>`_
or try browsing snmpfwd-users
`mailing list archives <https://sourceforge.net/p/snmpfwd/mailman/snmpfwd-users/>`_.
