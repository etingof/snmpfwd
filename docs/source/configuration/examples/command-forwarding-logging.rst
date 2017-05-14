
Logging messages
================

The *logging* plugin to the SNMP Proxy Forwarder lets you record pieces of
passing SNMP messages to a file or to syslog. Log record format and content
is fully configurable.

For more information please refer to the :doc:`logger plugin documentation </configuration/plugins/logger>`.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed over SNMPv2c
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/command-forwarding-logging/server.conf

:download:`Download </../../conf/command-forwarding-logging/server.conf>` server configuration file.

Plugin configuration
++++++++++++++++++++

The *logger* plugin is configured at the client side to:

* write key facts about passing SNMP GET request and RESPONSE PDUs into a local file
* double-quote var-bindings values
* autorotate log file daily
* keep no more than 30 log files

.. literalinclude:: /../../conf/command-forwarding-logging/plugins/logger.conf

:download:`Download </../../conf/command-forwarding-logging/plugins/logger.conf>` plugin configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* run command request (and response) PDUs through the *logger* plugin
* place inbound PDUs into SNMP v2c messages and forward them to public
  SNMP agent running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/command-forwarding-logging/client.conf

:download:`Download </../../conf/command-forwarding-logging/client.conf>` client configuration file.
