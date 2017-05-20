
Virtual network interfaces
==========================

In some use-cases it may be convenient to represent backend SNMP agents
(or parts of a single agent) as a set of independent SNMP agents at
the frontend, e.g. server side of SNMP Proxy Forwarder. In such cases
you could set up many virtual (AKA secondary) network interfaces at the
server host and configure SNMP Proxy Forwarder to route SNMP messages
based on their destination addresses.

This only works on Linux and requires Python 3.3+.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at all interfaces
* use POSIX *sendmsg()/recvmsg()* calls for the UDP socket by turning on the
  :ref:`virtual-interface <snmp-transport-options-server-option>` option
* distinguish messages sent to *127.0.0.1* from messages sent to *127.0.0.2*
* forward SNMP PDUs to different clients/trunks based on SNMP message
  destination address
* respond to queries, performed over SNMPv2c, from the same IP to which
  the request was sent

.. literalinclude:: /../../conf/command-forwarding-virtual-interfaces/server.conf

:download:`Download </../../conf/command-forwarding-virtual-interfaces/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* use POSIX *sendmsg()/recvmsg()* calls for the UDP socket by turning on the
  :ref:`virtual-interface <snmp-transport-options-client-option>` option
* place inbound PDUs into SNMP v2c messages and forward them towards SNMP agent
  running at *demo.snmplabs.com*

.. literalinclude:: /../../conf/command-forwarding-virtual-interfaces/client.conf

:download:`Download </../../conf/command-forwarding-virtual-interfaces/client.conf>` client configuration file.
