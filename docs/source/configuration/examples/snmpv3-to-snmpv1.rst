
SNMPv3 to SNMPv1 proxy
======================

In this configuration SNMP Proxy Forwarder performs translation
between SNMP versions.

You could test this configuration by running:

.. code-block:: bash

    $ snmpwalk -v3 -lauthPriv -u test-user  -A authkey1 -X privkey1 127.0.0.1:1161 system

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed as an SNMPv3 USM user
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/snmpv3-to-snmpv1/server.conf

:download:`Download </../../conf/snmpv3-to-snmpv1/server.conf>` configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* place inbound PDUs into SNMP v1 messages and forward them to public
  SNMP agent running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/snmpv3-to-snmpv1/client.conf

:download:`Download </../../conf/snmpv3-to-snmpv1/client.conf>` configuration file.
