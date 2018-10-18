
Trunk connection over IPv6
==========================

In some settings it may be desired to span SNMP Proxy Forwarder across IPv6 network.
The SNMP traffic is independent, it can run over IPv4 or IPv6 network.

To configure trunk connection over IPv6 network, IPv6 addresses should be set to
all the trunk addressing options e.g.
:ref:`trunk-bind-address-client-option`, :ref:`trunk-bind-address-server-option`
:ref:`trunk-peer-address-client-option` and :ref:`trunk-peer-address-server-option`.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed over SNMPv2c
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode over IPv6 network

.. literalinclude:: /../../conf/command-forwarding-trunk-ipv6/server.conf

:download:`Download </../../conf/command-forwarding-trunk-ipv6/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection at a IPv6 network
* process all incoming SNMP messages in the same way
* run command request (and response) PDUs through the *logger* plugin
* place inbound PDUs into SNMP v2c messages and forward them to public
  SNMP agent running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/command-forwarding-trunk-ipv6/client.conf

:download:`Download </../../conf/command-forwarding-trunk-ipv6/client.conf>` client configuration file.
