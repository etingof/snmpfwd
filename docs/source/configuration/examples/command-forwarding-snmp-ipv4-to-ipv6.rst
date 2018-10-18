
IPv4 to IPv6 translation
========================

SNMP engines built into client and server pieces of SNMP Forwarder can
operate over different network transports, namely different IP protocol
versions.

The following example demonstrates SNMP command forwarder performing
IPv4 to IPv6 translation of SNMP traffic along the way.

You could test this configuration by running:

.. code-block:: bash

    $ snmpwalk -v2c -c public 127.0.0.1:1161 system

.. note::

   The example configuration attempt to query public SNMP agent at *demo.snmplabs.com* over
   IPv6. This might work if global IPv6 routing is available on your local network.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on IPv4 address
* respond to queries performed over SNMPv2c
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/command-forwarding-snmp-ipv4-to-ipv6/server.conf

:download:`Download </../../conf/command-forwarding-snmp-ipv4-to-ipv6/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* place inbound PDUs into SNMP v2c messages and forward them to public
  SNMP agent at *demo.snmplabs.com* over IPv6 network

.. literalinclude:: /../../conf/command-forwarding-snmp-ipv4-to-ipv6/client.conf

:download:`Download </../../conf/command-forwarding-snmp-ipv4-to-ipv6/client.conf>` client configuration file.
