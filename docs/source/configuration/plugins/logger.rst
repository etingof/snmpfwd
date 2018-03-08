
The *logger* plugin
===================

The *logger* plugin can record contents, properties and effective system configuration of
the passing SNMP messages into a local file or send log message over to the
syslog service.

Plugin options
--------------

One or more options could be passed to the plugin via the
:ref:`plugin-options <plugin-options-server-option>` server
and/or client configuration option.

The values to the *plugin-options* setting must be one or more
key-value pairs separated via the equal sign (*=*). The following
plugin options are recognized.

*config*
++++++++

Path to plugin configuration file.

This option can reference :ref:`config-dir <config-dir-macro>` macro.

.. _logger-config:

Configuration syntax
--------------------

The *logger* plugin configuration file takes shape of an .ini file. The .ini file
holds options within sections. The following chapters briefly describe available
options in form of *section.option*.

*general.method*
++++++++++++++++

The logging method: either *file* or *syslog*.

*file.destination*
++++++++++++++++++

Sets path to log file.

*file.rotation*
+++++++++++++++

Sets the criterion for log file rotation. Valid value is *timed*.

*file.backupcount*
++++++++++++++++++

Sets the limit for rotated files being kept on the filesystem.

*file.timescale*
++++++++++++++++

Together with the *file.interval* option defines the frequency of
file rotation. Valid values are:

* S - *file.interval* is measured in seconds
* M - *file.interval* is measured in minutes
* H - *file.interval* is measured in hours
* D - *file.interval* is measured in days

*file.interval*
+++++++++++++++

Together with the *file.timescale* option defines the frequency of
file rotation.

*syslog.facility*
+++++++++++++++++

Sets the syslog service facility to use for messages being generated.

*syslog.priority*
+++++++++++++++++

Sets syslog service priority for the messages being generated. Valid values are *DEBUG*,
*INFO*, *NOTICE*, *ERROR*, *CRITICAL*.

*syslog.transport*
++++++++++++++++++

Sets network transport to use by the syslog client to talk to the syslog service.

*content.pdus*
++++++++++++++

Sets SNMP PDU types to process. Non-matching PDUs will not be logged. Valid PDU types are
*GetRequest*, *GetNextRequest*, *SetRequest*, *GetBulkRequest*, *InformRequest*,
*SNMPv2Trap*, *Response*.

*content.template*
++++++++++++++++++

Log message template optionally containing `macros`_ to be expanded in the context of
passing SNMP message.

*content.parentheses*
+++++++++++++++++++++

Values in SNMP PDU variable-bindings may contain whitespaces. The *parentheses* option
may contain two characters or strings which will surround each value in the variable-bindings
being logged.

.. _logger-macros:

Macros
------

Many of the macros described below have the same name and meaning as the
:ref:`system configuration macros <snmp-macros>`.

*snmp-transport-domain*
+++++++++++++++++++++++

Expands into an OID identifying the type and instance of network transport
being used for processing this SNMP request.

*snmp-bind-address*
+++++++++++++++++++

Expands into SNMP message original destination address.

*snmp-bind-port*
++++++++++++++++

Expands into SNMP message original destination UDP port.

*snmp-peer-address*
+++++++++++++++++++

Expands into SNMP message original source address.

*snmp-peer-port*
++++++++++++++++

Expands into SNMP message original source UDP port.

*snmp-engine-id*
++++++++++++++++

Expands into local SNMP engine ID serving the request being processed.

*snmp-context-engine-id*
++++++++++++++++++++++++

Expands into SNMP context engine ID as set in SNMPv3 message header.

*snmp-context-name*
+++++++++++++++++++

Expands into SNMP context name as set in SNMPv3 message header.

*snmp-security-model*
+++++++++++++++++++++

Expands into SNMP security model being used for SNMP message being processed.
Possible values are:

* 1 - SNMP v1
* 2 - SNMP v2c
* 3 - SNMP v3

*snmp-security-level*
+++++++++++++++++++++

Expands into SNMP security level being used for SNMP message being processed.
Possible values are:

* 1 - no message authentication and encryption
* 2 - do message authentication, do not do encryption
* 3 - do both authentication and encryption

*snmp-security-name*
++++++++++++++++++++

Expands into SNMP security name being used for SNMP request being processed.

*snmp-var-binds*
++++++++++++++++

Expands into a space-separated list of space-separated oid-value pairs. Values
can optionally be surrounded by the `content.parentheses`_.

*asctime* and *isotime*
+++++++++++++++++++++++

Expands into a human-friendly representation of current date and time in local timezone:

* *${asctime}:* Fri Jun  2 00:15:46 2017
* *${isotime}:* 2017-06-02T00:15:46.59

*timestamp* and *uptime*
++++++++++++++++++++++++

Expands into a floating point number representing the number of seconds passed since
start if UNIX epoch or SNMP Proxy Forwarder process start respectively:

* *${timestamp}:* 1496354552.59
* *${uptime}:* 0003600.59

*callflow-id*
+++++++++++++

Expands into a semi-unique identifier associated with the SNMP message
being forwarded. This identifier stays the same at server and client
parts.

.. _logger-examples:

Example configuration
---------------------

The following example logs important pieces of SNMP command request
and response messages into a local file.

.. code-block:: bash

    [general]
    method: file

    [file]
    destination: /tmp/snmpfwd-brief.log

    [content]
    pdus: GetRequest GetNextRequest SetRequest GetBulkRequest Response
    template: ${timestamp} ${callflow-id} ${snmp-peer-address} ${snmp-pdu-type} ${snmp-var-binds}

This configuration forwards important facts about passing SNMP RESPONSE PDUs to the syslog service:

.. code-block:: bash

    [general]
    method: syslog

    [syslog]
    facility: LOCAL1
    priority: INFO
    transport: udp

    [content]
    pdus: Response
    template: ${snmp-peer-address} ${snmp-security-name} ${snmp-var-binds}
    parentheses: < >

For more information please refer to :doc:`the full configuration example </configuration/examples/command-forwarding-logging>`.
