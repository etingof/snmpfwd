
Rewriting values
================

SNMP Proxy Forwarder can be configured to change the value part
of SNMP PDU variable-bindings into something else.

This PDU modification is done by configuring the `rewrite.py` plugin module
to pass command response PDUs through it thus letting the plugin get hold on
the response variable-bindings.

You could test this configuration by running:

.. code-block:: bash

    # this should return modified *sysDescr.0* value
    $ snmpget -v1 -c public 127.0.0.1:1161 sysDescr.0

    # this should zero out *system* branch values
    $ snmpwalk -v1 -c public 127.0.0.1:1161 system

For more information please refer to the :doc:`rewrite plugin documentation </configuration/plugins/rewrite>`.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed over SNMPv2c
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode
* run variable-bindings in response PDU through the "rewrite.py" plugin
  changing matching variable-bindings

.. literalinclude:: /../../conf/command-forwarding-rewriting-response/server.conf

:download:`Download </../../conf/command-forwarding-rewriting-response/server.conf>` server configuration file.

Plugin configuration
++++++++++++++++++++

The *rewrite* plugin is configured at the server part to add a note into
sysDescr.0 and nullify all values in the "system" branch.

.. literalinclude:: /../../conf/command-forwarding-rewriting-response/plugins/rewrite.conf

:download:`Download </../../conf/command-forwarding-rewriting-response/plugins/rewrite.conf>` plugin configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* place inbound PDUs into SNMP v2c messages and forward them to public
  SNMP agent running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/command-forwarding-rewriting-response/client.conf

:download:`Download </../../conf/command-forwarding-rewriting-response/client.conf>` client configuration file.
