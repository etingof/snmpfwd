
IPv6 to IPv4 translation
========================

SNMP engines built into client and server pieces of SNMP Forwarder can
operate over different network transports, namely different IP protocol
versions.

The following example demonstrates SNMP command forwarder performing
IPv6 to IPv4 translation of SNMP traffic along the way.

You could test this configuration by running:

.. code-block:: bash

    $ snmpwalk -v2c -c public udp6:[::1]:1161 system

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on IPv6 address
* respond to queries performed over SNMPv2c
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/command-forwarding-snmp-ipv6-to-ipv4/server.conf

:download:`Download </../../conf/command-forwarding-snmp-ipv6-to-ipv4/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* place inbound PDUs into SNMP v2c messages and forward them to public
  SNMP agent at *demo.snmplabs.com* over IPv4 network

.. literalinclude:: /../../conf/command-forwarding-snmp-ipv6-to-ipv4/client.conf

:download:`Download </../../conf/command-forwarding-snmp-ipv6-to-ipv4/client.conf>` client configuration file.
