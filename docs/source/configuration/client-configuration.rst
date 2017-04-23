
Client configuration
====================

Client part acts as the SNMP manager side of the SNMP proxy system.
It is normally linked with one or more :doc:`servers <server-configuration>`
via *trunks*.

Basic configuration strategy for the client part is:

* Configure SNMP credentials and targets to communicate with. Each target
  is identified by `snmp-peer-id`_.

* Configure server<->client communication link(s) called "trunks". Both
  client and server could initiate and/or receive trunking
  connections. Each trunk is identified by `trunk-id`_ which is used
  for message routing. Trunk initiator is responsible for `trunk-id`_
  definition.

* Describe original SNMP credentials and peers used by the server part
  of the SNMP Forwarder to communicate with its SNMP Managers. Each peer
  (or a group of them) is identified by `orig-snmp-peer-id`_.

* Configure message routing in form of `matching-trunk-id-list`_ and
  `matching-orig-snmp-peer-id-list`_ options mapped to the
  contents of `using-snmp-peer-id-list`_ option. The latter lists
  `snmp-peer-id`_'s to forward SNMP messages to.

Global options
--------------

*config-version*
++++++++++++++++

Program name to consume this configuration file. Valid values are *snmpfwd-client*
and *snmpfwd-server*.

*program-name*
++++++++++++++

Program name to add to log file messages. May be useful when multiple instances
of the system share the same log file.

SNMP manager options
--------------------

*snmp-engine-id*
++++++++++++++++

SNMP engine identifier to configure to SNMP engine ID instance within SNMP
Proxy Forwarder (server or client). A single instance of server or client
can have many independent SNMP engine instances running.

Example:

.. code-block:: bash

    snmp-engine-id: 0x0102030405070809

*snmp-transport-domain*
+++++++++++++++++++++++

Configures two things at once:

* type of network transport (UDP/IPv4 or UDP/IPv6)
* instance of network connection endpoint to refer SNMP agent/manager to

Transport type is determined by OID prefix, while endpoint instance - by
OID suffix

Recognized OID prefixes are:

* UDP/IPv4 - *1.3.6.1.6.1.1*
* UDP/IPv6 - *1.3.6.1.2.1.100.1.2*

Any integer value can serve as OID suffix.

Example:

.. code-block:: bash

    snmp-transport-domain: 1.3.6.1.6.1.1.123
    snmp-bind-address: 127.0.0.1:5555

Where *1.3.6.1.6.1.1* identifies UDP-over-IPv4 transport and *123* identifies
transport endpoint listening at address 127.0.0.1, UDP port 5555.

*snmp-transport-options*
++++++++++++++++++++++++

Enable specific networking options. Valid values:

* *transparent-proxy* - sending requests from a spoofed IP address,
  e.g. if there is no such local IP interface exists.

* *virtual-interface* - enables sending requests from any local address
  without explicitly binding to it.

.. note::

    Both options only work on Linux and require Python 3.3+.

*snmp-bind-address*
+++++++++++++++++++

Originate SNMP packets from this transport address endpoint.

The *${snmp-peer-address}* macro could be used as a value to make
client sending SNMP query from the source address of the original
SNMP manager that sends SNMP query (AKA spoofing). This option
effectively hides SNMP Proxy Forwarder from SNMP agents giving
them an illusion that they communicate directly with SNMP managers.

See `snmp-transport-options`_ for related options and
:doc:`server-side configuration <server-configuration>`.

.. note::

    Additional network configuration is required on the network to make
    SNMP response packets reaching the host where SNMP Proxy Forwarder
    is running and accepting them by the host.

*snmp-peer-address*
+++++++++++++++++++

Send SNMP packets to this network address.

The *${snmp-bind-address}* macro could be used as a value to make
client sending SNMP query to the destination address of the original
SNMP query. This option effectively hides SNMP Proxy Forwarder
from SNMP managers turning it into transparent SNMP proxy.

See `snmp-transport-options`_ for related options.

*snmp-peer-timeout*
+++++++++++++++++++

SNMP request timeout in seconds.

*snmp-peer-retries*
+++++++++++++++++++

How many times to retry timed-out SNMP request.

*snmp-security-model*
+++++++++++++++++++++

SNMP version to use. Valid values are:

* *0* - SNMP v1
* *1* - SNMP v2c
* *3* - SNMP v3

*snmp-security-level*
+++++++++++++++++++++

SNMPv3 security level to use. Valid values are

* *1* - no message authentication and encryption
* *2* - do message authentication, do not do encryption
* *3* - do both authentication and encryption

*snmp-security-name*
++++++++++++++++++++

Identifier for SNMP user configuration entry. In most cases can be set
to the same value as `snmp-community-name`_ or `snmp-usm-user`_.

*snmp-community-name*
+++++++++++++++++++++

SNMP community string for SNMP v1/v2c.

*snmp-usm-user*
+++++++++++++++

SNMPv3 USM username.

*snmp-usm-auth-protocol*
++++++++++++++++++++++++

SNMPv3 message authentication protocol to use. Valid values are:

* *1.3.6.1.6.3.10.1.1.1* - no authentication
* *1.3.6.1.6.3.10.1.1.2* - the HMAC-MD5-96 Digest Authentication Protocol (:RFC:`3414#section-6`)
* *1.3.6.1.6.3.10.1.1.3* - the HMAC-SHA-96 Digest Authentication Protocol (:RFC:`3414#section-7`)

*snmp-usm-auth-key*
+++++++++++++++++++

SNMPv3 message authentication key.

.. note::

    Must be 8 or more characters.

*snmp-usm-priv-protocol*
++++++++++++++++++++++++

SNMPv3 message encryption protocol to use. Valid values are:

* *1.3.6.1.6.3.10.1.2.1* - no encryption
* *1.3.6.1.6.3.10.1.2.2* - CBC-DES Symmetric Encryption Protocol (:RFC:`3414#section-8`)
* *1.3.6.1.6.3.10.1.2.3* - CBC-3DES Symmetric Encryption Protocol `reeder-snmpv3-usm-3desede <https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00#section-5>`_
* *1.3.6.1.6.3.10.1.2.4* - CFB128-AES-128 Symmetric Encryption Protocol (:RFC:`3826#section-3`)
* *1.3.6.1.4.1.9.12.6.1.1* - CFB128-AES-192 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_) with Reeder key localization
* *1.3.6.1.4.1.9.12.6.1.2* - CFB128-AES-256 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_) with Reeder key localization

*snmp-usm-priv-key*
+++++++++++++++++++

SNMPv3 message encryption key.

.. note::

    Must be 8 or more characters.

*snmp-context-engine-id*
++++++++++++++++++++++++

SNMPv3 Context Engine ID to use when sending SNMP messages towards SNMP agents.
The *${context-engine-id}* macro can be used as a value to instruct the client
to use context engine ID value from the original request.

*snmp-context-name*
+++++++++++++++++++

SNMPv3 Context Engine ID to use when sending SNMP messages towards SNMP agents.
The *${context-name}* macro can be used as a value to instruct the client
to use context name value from the original request.

*snmp-peer-id*
++++++++++++++

Unique identifier grouping together SNMP transport
endpoints and snmp credentials. In other words it identifies which
SNMP agent to talk to using which SNMP credentials via which
network transport endpoints.

Example:

.. code-block:: bash

    snmp-peer-A {
      snmp-transport-domain: 1.3.6.1.6.1.1.1
      snmp-bind-address: 0.0.0.0:0
      snmp-peer-address: 104.236.166.95:161

      snmp-peer-timeout: 1
      snmp-peer-retries: 0

      snmp-community-name: abrakadabra
      snmp-security-name: abrakadabra
      snmp-security-model: 2

      snmp-peer-id: 101
    }

Trunking options
----------------

*trunk-bind-address*
++++++++++++++++++++

Local network endpoint address to bind trunk connection to.

*trunk-peer-address*
++++++++++++++++++++

Remote network endpoint address to connect to when establishing trunk connection.

*trunk-connection-mode*
+++++++++++++++++++++++

Trunk connection mode: *client* or *server*. Determines the originator
of the trunk connection. When in *client* mode, actively tries to establish
and maintain running connection with a peer. When in *server* mode, opens
TCP port and listens at it for *client* connections.

*trunk-crypto-key*
++++++++++++++++++

Shared secret key used for trunk connection encryption. Missing option disables
trunk encryption.

.. note::

    The key must be the same at both client and server for trunking link
    between them to establish.

*trunk-id*
++++++++++

Unique identifier of a single trunk connection. Client trunks determine
*trunk-id*, server-mode connections learn *trunk-id* from connecting
clients.

.. code-block:: bash

    trunking-group {
      trunk-crypto-key: 1234567890

      host-A {
        trunk-bind-address: 127.0.0.1
        trunk-peer-address: 127.0.0.1:30301
        trunk-connection-mode: client

        trunk-id: servertrunk
      }

      interface-1 {
        trunk-bind-address: 127.0.0.1:30201
        trunk-connection-mode: server

        trunk-id: <discover>
      }
    }

Matching SNMP properties
------------------------

Server part communicates to client all the aspects of the original SNMP query
that server received. Options that follow leverage that information for the
purpose of choosing SNMP manager to forward incoming SNMP packet to.

*orig-snmp-engine-id-pattern*
+++++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by their original SNMP engine ID.

*orig-snmp-transport-domain-pattern*
++++++++++++++++++++++++++++++++++++

A regular expression matching SNMP messages by the SNMP transport domain through which
they are received.

*orig-snmp-peer-address-pattern*
++++++++++++++++++++++++++++++++

A regular expression matching SNMP messages by their original source network
address.

*orig-snmp-bind-address-pattern*
++++++++++++++++++++++++++++++++

A regular expression matching SNMP messages by their original destination network
address.

*orig-snmp-security-model-pattern*
++++++++++++++++++++++++++++++++++

A regular expression matching SNMP messages by their original security
model.

*orig-snmp-security-name-pattern*
+++++++++++++++++++++++++++++++++

A regular expression matching SNMP messages by their original security
name.

*orig-snmp-security-level-pattern*
++++++++++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by their original security
level value.

*orig-snmp-context-engine-id-pattern*
+++++++++++++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by their original context
engine ID.

*orig-snmp-context-name-pattern*
++++++++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by their original context
name.

*orig-snmp-pdu-type-pattern*
++++++++++++++++++++++++++++

A regular expression matching SNMP messages by their PDU type. Recognized values are: *GET*,
*SET*, *GETNEXT*, *GETBULK*.

*orig-snmp-oid-prefix-pattern*
++++++++++++++++++++++++++++++

A regular expression matching OIDs in SNMP PDU.

Example:

.. code-block:: bash

    orig-snmp-oid-prefix-pattern: 1\.3\.6\.1\.2\.1\.2\.1\.0|1\.3\.6\.1\.2\.1\.2\.2\.0

*orig-snmp-peer-id*
+++++++++++++++++++

Unique identifier grouping a collection of *orig-\** identifiers under a single ID.
The *orig-snmp-peer-id* identifier is typically used in message routing tables.

Example:

.. code-block:: bash

    snmp-peer-A {
      orig-snmp-transport-domain-pattern: 1\.3\.6\.1\.6\.1\.1\.100
      orig-snmp-peer-address-pattern: 127\.0\.0\.1:[0-9]*

      orig-snmp-security-name-pattern: public
      orig-snmp-security-model-pattern: 1

      orig-snmp-peer-id: snmpv1-manager-at-localhost
    }

Message routing
---------------

The purpose of the routing is to determine backend SNMP agent to
forward message to, using which SNMP credentials and at what
network address.

This is done by searching for a combination of matching IDs.

*matching-trunk-id-list*
++++++++++++++++++++++++

Evaluates to True if SNMP request message comes from one of `trunk-id`_'s present
in the list.

*matching-orig-snmp-peer-id-list*
+++++++++++++++++++++++++++++++++

Evaluates to True if original SNMP request message properties match
any of `orig-snmp-peer-id`_'s in the list.

*using-snmp-peer-id-list*
+++++++++++++++++++++++++

Unique identifier matching a group of *matching-\** identifiers. Specifically,
these are: `matching-trunk-id-list`_, `matching-orig-snmp-peer-id-list`_
and `using-snmp-peer-id-list`_.

SNMP request message will be passed to to each `snmp-peer-id`_'a present
in the list.

Example:

.. code-block:: bash

    routing-map {
      route-1 {
        matching-trunk-id-list: frontend-server-trunk
        matching-orig-snmp-peer-id-list: manager-123
        using-snmp-peer-id-list: backend-agent-A
      }
    }
