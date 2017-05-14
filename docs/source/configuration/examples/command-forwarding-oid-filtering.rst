
Filtering OIDs
==============

The SNMP Proxy Forwarder configuration described in this example is
designed to hide portions of the MIB, as implemented by the agents
on one side of SNMP Proxy, from SNMP managers at the other side of
SNMP Proxy.

The filtering is done by configuring the `oidfilter.py` plugin module
to pass command and notification PDUs through it thus letting the plugin
to interfere and clean up unwanted OIDs in response.

You could test this configuration by running:

.. code-block:: bash

    # this should fail
    $ snmpget -v1 -c public 127.0.0.1:1161 sysDescr.0

    # this should succeed
    $ snmpget -v1 -c public 127.0.0.1:1161 sysLocation.0

For more information please refer to the :doc:`oidfilter plugin documentation </configuration/plugins/oidfilter>`.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed over SNMPv2c
* for GET/SET/GETNEXT PDUs, take blocked OIDs out of request PDU (but remember them)
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode
* reconstruct original OIDs in response PDU using blocked OIDs from GET/GETNEXT/SET
  request PDU and allowed OIDs from response PDU

.. literalinclude:: /../../conf/command-forwarding-filtering/server.conf

:download:`Download </../../conf/command-forwarding-filtering/server.conf>` server configuration file.

Plugin configuration
++++++++++++++++++++

The *oidfilter* plugin is configured at the server side to pass just a
few specific OIDs and branches blocking the rest of the MIB tree that
backend SNMP agent serve.

.. literalinclude:: /../../conf/command-forwarding-filtering/plugins/oidfilter.conf

:download:`Download </../../conf/command-forwarding-filtering/plugins/oidfilter.conf>` plugin configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* place inbound PDUs into SNMP v2c messages and forward them to public
  SNMP agent running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/command-forwarding-filtering/client.conf

:download:`Download </../../conf/command-forwarding-filtering/client.conf>` client configuration file.
