
Server configuration
====================

Server part acts as the SNMP agent side of the SNMP proxy system.
It is normally linked with one or more :doc:`clients <client-configuration>`
via *trunks*.

Basic configuration strategy for the server part is:

* Configure SNMP credentials and SNMP Agent(s) listening for SNMP
  Managers to communicate with. Each Agent is identified by
  `snmp-credentials-id`_.

* Configure SNMP contexts. Each SNMP context is identified by
  `snmp-context-id`_ option.

* Configure individual SNMP Managers or groups of Managers. Each Manager
  or group is identified by the `snmp-peer-id`_ option.

* Configure server<->client communication link(s) called "trunks". Both
  Forwarder client and server could initiate and/or receive trunking
  connections. Each trunk is identified by a `trunk-id`_ which is used
  for message routing. Trunk initiator is responsible for `trunk-id`_
  definition.

* Optionally configure plugins. These are small Python code snippets
  capable to access/modify/block passing SNMP message. You should
  configure each module you intend to use (giving search path, module
  file name, options) and assign it `plugin-id`_. Then you could list
  these IDs in the routing section.

* Configure message routing in form of `matching-snmp-credentials-id-list`_,
  `matching-snmp-peer-id-list`_, `matching-snmp-content-id-list`_ and
  `matching-snmp-context-id-list`_ options mapped to the contents of
  `using-trunk-id-list`_. The latter identifies Manager part(s) of
  SNMP Forwarder to pass received SNMP message over.

Global options
--------------

*config-version*
++++++++++++++++

Configuration file language version. Currently recognized version is *2*.

*program-name*
++++++++++++++

Program name to consume this configuration file. Valid values are *snmpfwd-client*
and *snmpfwd-server*.

SNMP agents options
-------------------

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

Enable advanced networking options. Valid values are:

* *transparent-proxy* - enables SNMP request-response communication at any
  IP address, even if such IP interface does not exist at this system

* *virtual-interface* - enables SNMP request-response communication via
  a secondary IP interface and learns actual destination IP address
  used by the Manager regardless of the one we are bound to

The *transparent-proxy* option effectively hides SNMP Proxy Forwarder from SNMP
agents giving them an illusion that they communicate directly with SNMP managers.

See also :doc:`client-side configuration <client-configuration>`.

.. note::

    Additional network configuration is required on the network to make
    SNMP request packets reaching the host where SNMP Proxy Forwarder
    is running and accepting them by the host.

*snmp-bind-address*
+++++++++++++++++++

Listen for SNMP packets at this network address. Example:

.. code-block:: bash

    udp-listener-123 {
        snmp-transport-domain: 1.3.6.1.6.1.1.200
        snmp-bind-address: 127.0.0.1:161
        snmp-credentials-id: agent-10
    }

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

*snmp-credentials-id*
+++++++++++++++++++++

Unique identifier of a collection of SNMP configuration options. Used to
assign specific SNMP configuration to a particular SNMP entity. Can also be
used to share the same SNMP configuration among multiple SNMP entities.

Example:

.. code-block:: bash

    my-snmpv3-user {
      snmp-security-level: 3
      snmp-security-name: test-user

      snmp-usm-user: test-user
      snmp-usm-auth-protocol: 1.3.6.1.6.3.10.1.1.2
      snmp-usm-auth-key: authkey1
      snmp-usm-priv-protocol: 1.3.6.1.6.3.10.1.2.2
      snmp-usm-priv-key: privkey1

      snmp-transport-domain: 1.3.6.1.6.1.1.200
      snmp-bind-address: 127.0.0.1:161

      snmp-credentials-id: snmpv3-agent-at-localhost
    }

Plugin options
--------------

*plugin-modules-path-list*
++++++++++++++++++++++++++

Directory search path for plugin modules.

*plugin-module*
+++++++++++++++

Plugin module file name to load and run (without .py).

*plugin-options*
++++++++++++++++

Plugin-specific configuration option to pass to plugin.

*plugin-id*
+++++++++++

Unique identifier of a plugin module (`plugin-module`_) and its
options (`plugin-options`_). The *plugin-id* identifier is
typically used to invoke plugin in the course of SNMP message
processing.

Example:

.. code-block:: bash

    rewrite-plugin {
      plugin-module: rewrite
      plugin-options: config=/etc/snmpfwd/plugins/rewrite.conf

      plugin-id: rewrite
    }

    logging-plugin {
      plugin-module: logger
      plugin-options: config=/etc/snmpfwd/plugins/logger.conf

      plugin-id: logger
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

SNMP context matching
---------------------

*snmp-context-engine-id-pattern*
++++++++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by SNMP context engine ID.

*snmp-context-name-pattern*
+++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by SNMP context name.

*snmp-context-id*
+++++++++++++++++

Unique identifier of a collection of SNMP context configuration options. Used for
matching SNMP context options in inbound SNMP messages
(e.g. `snmp-context-engine-id-pattern`_, `snmp-context-name-pattern`_) for
message routing purposes.

Example:

.. code-block:: bash

    context-group {
      snmp-context-engine-id-pattern: .*
      snmp-context-name-pattern: .*

      snmp-context-id: any-context
    }

SNMP PDU contents matching
--------------------------

*snmp-pdu-type-pattern*
+++++++++++++++++++++++

A regular expression matching SNMPv3 messages by SNMP PDU type.
Recognized PDU types are: *GET*, *SET*, *GETNEXT*, *GETBULK*.

*snmp-pdu-oid-prefix-pattern-list*
++++++++++++++++++++++++++++++++++

List of regular expressions matching OIDs in SNMP PDU var-binds.

*snmp-content-id*
+++++++++++++++++

Unique identifier of a collection of SNMP content matching options. Used for
matching the contents of inbound SNMP messages (e.g.
`snmp-pdu-type-pattern`_, `snmp-pdu-oid-prefix-pattern-list`_) for
message routing purposes.

Example:

.. code-block:: bash

    content-group {
      write-pdu-group {
        snmp-pdu-type-pattern: SET
        snmp-content-id: set-content
      }

      oid-subtree-group {
        snmp-pdu-oid-prefix-pattern-list: 1\.3\.6\.1\.2\.1\.2\..*
        snmp-content-id: oid-subtree-content
      }

      others {
        snmp-content-id: any-content
      }
    }

Network peers matching
----------------------

*snmp-peer-address-pattern-list*
++++++++++++++++++++++++++++++++

List of regular expressions matching source transport endpoints
of SNMP message.

*snmp-bind-address-pattern-list*
++++++++++++++++++++++++++++++++

List of regular expressions matching destination transport endpoints
of SNMP message.

*snmp-peer-id*
++++++++++++++

Unique identifier matching pairs of source and destination SNMP transport
endpoints. Most importantly, `snmp-bind-address-pattern-list`_ and
`snmp-peer-address-pattern-list`_ as well as `snmp-transport-domain`_.
The *snmp-peer-id* is typically used for message routing purposes.

Example:

.. code-block:: bash

    peers-group {
      snmp-transport-domain: 1.3.6.1.6.1.1.100
      snmp-peer-address-pattern-list: 10\.113\..*
      snmp-bind-address-pattern-list: 127\.0\.0\.[2-3]:[0-9]*

      snmp-peer-id: 101
    }

Message routing
---------------

The purpose of these settings is to determine:

* plugin ID to pass SNMP message through
* trunk ID to pass SNMP message to

This is done by searching for a combination of matching IDs.

*matching-snmp-context-id-list*
+++++++++++++++++++++++++++++++

Evaluates to True if incoming SNMP message matches at least one
of `snmp-context-id`_ in the list.

*matching-snmp-content-id-list*
+++++++++++++++++++++++++++++++

Evaluates to True if incoming SNMP message matches at least one
of `snmp-content-id`_ in the list.

*matching-snmp-credentials-id-list*
+++++++++++++++++++++++++++++++++++

Evaluates to True if `snmp-credentials-id`_ used for processing incoming
SNMP message is present in the list.


*matching-snmp-peer-id-list*
++++++++++++++++++++++++++++

Evaluates to True if incoming SNMP message originates from and arrived at
one of the `snmp-peer-id`_ in the list.

*using-plugin-id-list*
++++++++++++++++++++++

Invoke each of the `plugin-id`_ in the list in order and and pass incoming
SNMP message from one to the other.

Plugins may modify the message in any way and even block it from further
propagation in which case SNMP message will be dropped.

*using-trunk-id-list*
+++++++++++++++++++++

Unique identifier matching a group of *matching-\** identifiers. Specifically,
these are: `matching-snmp-context-id-list`_, `matching-snmp-content-id-list`_,
`matching-snmp-credentials-id-list`_ and `matching-snmp-peer-id-list`_.

Incoming (and possibly modified) SNMP message will be passed to to each
`trunk-id`_ present in the list.

Example:

.. code-block:: bash

    routing-map {
      matching-snmp-context-id-list: any-context
      matching-snmp-content-id-list: any-content

      route-1 {
        matching-snmp-credentials-id-list: config-1 config-2 config-121
        matching-snmp-content-id-list: if-subtree-content
        matching-snmp-peer-id-list: 100 111

        using-plugin-id-list: logger rewrite
        using-trunk-id-list: clienttrunk
      }
    }
