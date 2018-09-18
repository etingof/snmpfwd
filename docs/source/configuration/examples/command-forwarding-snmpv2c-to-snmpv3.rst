
SNMPv2c to SNMPv3 proxy
=======================

In this configuration SNMP Proxy Forwarder performs translation
between SNMP versions.

You could test this configuration by running:

.. code-block:: bash

    $ snmpwalk -v2c -c public 127.0.0.1:1161 system

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed as an SNMPv2c SNMP agent
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/command-forwarding-snmpv2c-to-snmpv3/server.conf

:download:`Download </../../conf/command-forwarding-snmpv2c-to-snmpv3/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* place inbound PDUs into SNMPv3 messages and forward them to public
  SNMP agent running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/command-forwarding-snmpv2c-to-snmpv3/client.conf

:download:`Download </../../conf/command-forwarding-snmpv2c-to-snmpv3/client.conf>` client configuration file.
