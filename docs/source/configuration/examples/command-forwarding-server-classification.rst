
Server-centric message routing
==============================

In some use-cases it may be desirable to perform peer classification
at the server side and let client(s) re-using the outcome of server
classification. The example configuration explains server-based
classification design.

For more information please refer to the :ref:`client configuration documentation <matching-server-classification-client-chapter>`.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* respond to queries performed over SNMPv2c
* serve two distinct SNMP community names
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/command-forwarding-server-classification/server.conf

:download:`Download </../../conf/command-forwarding-server-classification/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* process all incoming SNMP messages in the same way
* route inbound SNMP PDUs into either of two backend
  SNMP agents (at *demo.snmplabs.com*) chosen based
  on :ref:`server-classification-id <server-classification-id-client-option>`
  option.

.. literalinclude:: /../../conf/command-forwarding-server-classification/client.conf

:download:`Download </../../conf/command-forwarding-server-classification/client.conf>` client configuration file.
