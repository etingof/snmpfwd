
TRAP forwarder, SNMPv2c
=======================

In this configuration SNMP Proxy Forwarder performs SNMP TRAP forwarding not
changing SNMP version on the way.

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

    $ snmptrap -v2c -c public 127.0.0.1:1161 12345 1.3.6.1.2.5 sysDescr s myagent

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* expect SNMP TRAP packets sent over SNMPv2c, community name "public"
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. warning::

    Since SNMP TRAP is always a one-way communication, SNMPv3 parties can't
    negotiate authoritative SNMP engine ID automatically which is used
    for authentication and encryption purposes.

    When SNMPv3 authentication or encryption services are being used, it is
    required to statically configure SNMP engine ID of the TRAP sender
    at SNMP Proxy Forwarder server configuration.

.. literalinclude:: /../../conf/trap-forwarding-snmpv2c/server.conf

:download:`Download </../../conf/trap-forwarding-snmpv2c/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* place inbound TRAP PDUs into SNMP v2c messages and forward them to public
  SNMP manager running at *demo.snmplabs.com*

.. warning::

    Since SNMP TRAP is always a one-way communication, SNMPv3 parties can't
    negotiate authoritative SNMP engine ID automatically which is used
    for authentication and encryption purposes.

    When SNMPv3 authentication or encryption services are being used, it is
    required to statically configure SNMP engine ID of the TRAP receiver
    at SNMP Proxy Forwarder client configuration.

.. literalinclude:: /../../conf/trap-forwarding-snmpv2c/client.conf

:download:`Download </../../conf/trap-forwarding-snmpv2c/client.conf>` client configuration file.
