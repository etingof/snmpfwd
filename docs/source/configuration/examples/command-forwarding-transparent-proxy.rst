
Transparent proxy
=================

SNMP Proxy Forwarder can turn fully stealth meaning that neither frontend
SNMP managers nor backend SNMP agents are aware of the proxy existence
in between them.

The workflow scenario could be like this:

* SNMP managers send SNMP queries to SNMP agents they know about
* The network routes request packets from SNMP managers to the
  SNMP Proxy Forwarder host where its server part is running
* The request gets forwarded to the client part which then sends it towards
  SNMP agent:

   * to the destination address originally used by SNMP manager
   * spoofing source address to the SNMP manager's one

* The network routes response packets from SNMP agent destined to
  SNMP manager address to the SNMP Proxy Forwarder host where its
  client part is running

This only works on Linux, requires Python 3.3+ and superuser privileges.

Network configuration
---------------------

You need to configure your network routing in a way that SNMP packets
being sent by SNMP managers towards SNMP agents are routed to the host where
the server part of SNMP Proxy Forwarder is listening.

At that host, the following *iptables* configuration is suggested:

.. code-block:: bash

    # setup a chain DIVERT to mark packets
    iptables -t mangle -N DIVERT
    iptables -t mangle -A DIVERT -j MARK --set-mark 1
    iptables -t mangle -A DIVERT -j ACCEPT

    # use DIVERT to prevent packets bound to open socket going through TPROXY twice
    iptables  -t mangle -A PREROUTING -p udp -m socket -j DIVERT

    # mark all other (new) packets and use TPROXY to pass into snmpfwd listening at port 161
    iptables  -t mangle -A PREROUTING -p udp --dport 161 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 161

Once we have incoming SNMP packets identified, we need to source-route them
to the server part of SNMP proxy listening on *lo*:

.. code-block:: bash

    ip route flush table 100
    ip rule add fwmark 1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100

In some use-cases, packet forwarding should be enabled on the system:

.. code-block:: bash

    echo 1 >  /proc/sys/net/ipv4/ip_forward

For more information on Linux kernel TPROXY operation, please refer to the
`Linux kernel documentation <https://www.kernel.org/doc/Documentation/networking/tproxy.txt>`_.

.. toctree::
   :maxdepth: 2

Server configuration
--------------------

Server is configured to:

* listen on UDP socket at localhost
* turn UDP socket into :ref:`transparent-proxy <snmp-transport-options-server-option>` mode
* respond to queries performed over SNMPv2c
* forward all queries to snmpfwd client through an unencrypted trunk connection
  running in *client* mode

.. literalinclude:: /../../conf/command-forwarding-transparent-proxy/server.conf

:download:`Download </../../conf/command-forwarding-transparent-proxy/server.conf>` server configuration file.

Client configuration
--------------------

Client is configured to:

* listen on server-mode unencrypted trunk connection
* turn UDP socket it uses for communicating with SNMP agents into
  :ref:`transparent-proxy <snmp-transport-options-client-option>` mode
* place inbound PDUs into SNMP v2c messages and forward them to the address
  that SNMP manager used when sending packets to the server part
* spoof source address of the packets to the address of SNMP manager which
  sends the query

.. literalinclude:: /../../conf/command-forwarding-transparent-proxy/client.conf

:download:`Download </../../conf/command-forwarding-transparent-proxy/client.conf>` client configuration file.

