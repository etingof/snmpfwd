
TRAP forwarder, SNMPv2c to SNMPv3
=================================

In this configuration SNMP Proxy Forwarder receives SNMPv2c TRAP PDU
and forwards it as SNMPv3 TRAP PDU.

.. note::

    When forwarding SNMP notifications, server part receives TRAPs from SNMP
    agents, while client part forwards them towards Managers. This is opposite
    to SNMP commands forwarding where server parts is directed towards SNMP managers
    and client part talks to SNMP agents.

    This means that if you want to forward both SNMP command and notification
    packets, you'd need to run at least two pairs of servers and clients
    forwarding packets in opposite directions.

You could test this configuration by running:

.. code-block:: bash

    $ snmptrap -v2c -c public 127.0.0.1:1162 12345 1.3.6.1.2.5 sysDescr s myagent

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* expect SNMP TRAP packets sent over SNMPv2c, community name "public"
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/trap-forwarding-snmpv2c-to-snmpv3/server.conf

:download:`Download </../../conf/trap-forwarding-snmpv2c-to-snmpv3/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* place inbound TRAP PDUs into SNMP v3 messages and forward them to public
  SNMP manager running at *demo.snmplabs.com*

.. warning::

    Since SNMP TRAP is always a one-way communication, SNMPv3 parties can't
    negotiate authoritative SNMP engine ID automatically which is used
    for authentication and encryption purposes.

    When SNMPv3 authentication or encryption services are being used,
    *snmp-engine-id* of the client SNMP engine becomes the authoritative
    SNMP engine ID for the purpose of sending SNMPv3 TRAP. If the
    :ref:`snmp-security-engine-id <snmp-security-engine-id-client-option>`
    is configured, it overrides :ref:`snmp-engine-id <snmp-engine-id-client-option>`
    for the purpose of sending SNMP v3 notifications.

    The USM user table at the receiving end must be configured to accept
    messages from *snmp-engine-id* or *snmp-security-engine-id*.

.. literalinclude:: /../../conf/trap-forwarding-snmpv2c-to-snmpv3/client.conf

:download:`Download </../../conf/trap-forwarding-snmpv2c-to-snmpv3/client.conf>` client configuration file.
