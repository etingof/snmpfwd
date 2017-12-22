
Server configuration
====================

Server part acts as the SNMP agent side of the SNMP proxy system.
It is normally linked with one or more :doc:`clients <client-configuration>`
via *trunks*.

Basic configuration strategy for the server part is:

* Configure SNMP credentials and SNMP Agent(s) listening for SNMP
  Managers to communicate with. Each Agent is identified by
  `snmp-credentials-id-server-option`_.

* Configure SNMP contexts. Each SNMP context is identified by
  `snmp-context-id-server-option`_ option.

* Configure individual SNMP Managers or groups of Managers. Each Manager
  or group is identified by the `snmp-peer-id-server-option`_ option.

* Configure server<->client communication link(s) called "trunks". Both
  Forwarder client and server could initiate and/or receive trunking
  connections. Each trunk is identified by a `trunk-id-server-option`_ which is used
  for message routing. Trunk initiator is responsible for `trunk-id-server-option`_
  definition.

* Optionally configure plugins. These are small Python code snippets
  capable to access/modify/block passing SNMP message. You should
  configure each module you intend to use (giving search path, module
  file name, options) and assign it `plugin-id-server-option`_. Then you could list
  these IDs in the routing section.

* Configure message routing in form of `matching-snmp-credentials-id-list-server-option`_,
  `matching-snmp-peer-id-list-server-option`_, `matching-snmp-content-id-list-server-option`_ and
  `matching-snmp-context-id-list-server-option`_ options mapped to the contents of
  `using-trunk-id-list-server-option`_. The latter identifies Manager part(s) of
  SNMP Forwarder to pass received SNMP message over.

.. _global-options-server-chapter:

Global options
--------------

.. _config-version-server-option:

*config-version*
++++++++++++++++

Configuration file language version. Currently recognized version is *2*.

.. _program-name-server-option:

*program-name*
++++++++++++++

Program name to consume this configuration file. Valid values are *snmpfwd-client*
and *snmpfwd-server*.

.. _snmp-agents-options-server-chapter:

SNMP agents options
-------------------

.. _snmp-engine-id-server-option:

*snmp-engine-id*
++++++++++++++++

SNMP engine identifier that creates a new, independent instance of SNMP engine.
All other SNMP settings scoped within this *snmp-engine-id* apply to this
SNMP engine instance.

A single instance of SNMP Proxy Forwarder server or client can have many
independent SNMP engine instances running concurrently.

Example:

.. code-block:: bash

    {
        snmp-engine-id: 0x0102030405070809

        ... other SNMP settings for this SNMP engine
    }
    {
        snmp-engine-id: 0x090807060504030201

        ... other SNMP settings for this SNMP engine
    }

.. note::

    There is no correlation between *snmp-engine-id* configured
    at server and client parts of SNMP Proxy Forwarder. They can be the same
    or differ in any way.

.. _snmp-transport-domain-server-option:

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

.. _snmp-transport-options-server-option:

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

.. _snmp-bind-address-server-option:

*snmp-bind-address*
+++++++++++++++++++

Listen for SNMP packets at this network address. Example:

.. code-block:: bash

    udp-listener-123 {
        snmp-transport-domain: 1.3.6.1.6.1.1.200
        snmp-bind-address: 127.0.0.1:161
        snmp-credentials-id: agent-10
    }


.. note::

    If you want response SNMP messages to have source address of the SNMP request
    destination address (as opposed to primary network interface address when
    *snmp-bind-address* is set to *0.0.0.0*), make sure to enable the
    `snmp-transport-options-server-option`_ = *virtual-interface* option.

.. _snmp-security-model-server-option:

*snmp-security-model*
+++++++++++++++++++++

SNMP version to use. Valid values are:

* *1* - SNMP v1
* *2* - SNMP v2c
* *3* - SNMP v3

.. _snmp-security-level-server-option:

*snmp-security-level*
+++++++++++++++++++++

SNMPv3 security level to use. Valid values are

* *1* - no message authentication and encryption
* *2* - do message authentication, do not do encryption
* *3* - do both authentication and encryption

.. _snmp-security-name-server-option:

*snmp-security-name*
++++++++++++++++++++

Identifier that logically groups SNMP configuration settings together.

.. note::

    Must be unique within SNMP engine instance (e.g. `snmp-engine-id`_).

.. _snmp-community-name-server-option:

*snmp-community-name*
+++++++++++++++++++++

SNMP community string for SNMP v1/v2c.

.. _snmp-usm-user-server-option:

*snmp-usm-user*
+++++++++++++++

SNMPv3 USM username.

.. _snmp-usm-auth-protocol-server-option:

*snmp-usm-auth-protocol*
++++++++++++++++++++++++

SNMPv3 message authentication protocol to use. Valid values are:

+--------+----------------+-------------+
| *ID*   |  *Algorithm*   | *Reference* |
+--------+----------------+-------------+
| NONE   | -              | RFC3414     |
+--------+----------------+-------------+
| MD5    | HMAC MD5       | RFC3414     |
+--------+----------------+-------------+
| SHA    | HMAC SHA-1 128 | RFC3414     |
+--------+----------------+-------------+
| SHA224 | HMAC SHA-2 224 | RFC7860     |
+--------+----------------+-------------+
| SHA256 | HMAC SHA-2 256 | RFC7860     |
+--------+----------------+-------------+
| SHA384 | HMAC SHA-2 384 | RFC7860     |
+--------+----------------+-------------+
| SHA512 | HMAC SHA-2 512 | RFC7860     |
+--------+----------------+-------------+

.. _snmp-usm-auth-key-server-option:

*snmp-usm-auth-key*
+++++++++++++++++++

SNMPv3 message authentication key.

.. note::

    Must be 8 or more characters.

.. _snmp-usm-priv-protocol-server-option:

*snmp-usm-priv-protocol*
++++++++++++++++++++++++

SNMPv3 message encryption protocol to use. Valid values are:

+------------+------------------------+----------------------+
| *ID*       | *Algorithm*            | *Reference*          |
+------------+------------------------+----------------------+
| NONE       | -                      | RFC3414              |
+------------+------------------------+----------------------+
| DES        | DES                    | RFC3414              |
+------------+------------------------+----------------------+
| AES        | AES CFB 128            | RFC3826              |
+------------+------------------------+----------------------+
| AES192     | AES CFB 192            | RFC Draft            |
+------------+------------------------+----------------------+
| AES256     | AES CFB 256            | RFC Draft            |
+------------+------------------------+----------------------+
| AES192BLMT | AES CFB 192 Blumenthal | RFC Draft            |
+------------+------------------------+----------------------+
| AES256BLMT | AES CFB 256 Blumenthal | RFC Draft            |
+------------+------------------------+----------------------+
| 3DES       | Triple DES EDE         | RFC Draft            |
+------------+------------------------+----------------------+

.. _snmp-usm-priv-key-server-option:

*snmp-usm-priv-key*
+++++++++++++++++++

SNMPv3 message encryption key.

.. note::

    Must be 8 or more characters.

.. _snmp-credentials-id-server-option:

*snmp-credentials-id*
+++++++++++++++++++++

Unique identifier of a collection of SNMP configuration options. Used to
assign specific SNMP configuration to a particular SNMP entity. Can also be
used to share the same SNMP configuration among multiple SNMP entities.

This option can contain :ref:`SNMP macros <snmp-macros>`.

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

.. _plugin-options-server-chapter:

Plugin options
--------------

The plugin options instantiate a :ref:`plugin <plugins>` file with
specific configuration options and assign an identifier to it. You
can have many differently configured instances of the same plugin
module in the system.

.. note::

    Client-side plugins are also :ref:`available <plugin-options-client-chapter>`.

.. _plugin-modules-path-list-server-option:

*plugin-modules-path-list*
++++++++++++++++++++++++++

Directory search path for plugin modules.

This option can reference :ref:`config-dir <config-dir-macro>` macro.

.. _plugin-module-server-option:

*plugin-module*
+++++++++++++++

Plugin module file name to load and run (without .py).

.. _plugin-options-server-option:

*plugin-options*
++++++++++++++++

Plugin-specific configuration option to pass to plugin.

This option can reference :ref:`config-dir <config-dir-macro>` macro.

.. _plugin-id-server-option:

*plugin-id*
+++++++++++

Unique identifier of a plugin module (`plugin-module-server-option`_) and its
options (`plugin-options-server-option`_).

This option can reference :ref:`config-dir <config-dir-macro>` macro.

The *plugin-id* identifier is typically used to invoke plugin
in the course of SNMP message processing.

Example:

.. code-block:: bash

    rewrite-plugin {
      plugin-module: rewrite
      plugin-options: config=${config-dir}/plugins/rewrite.conf

      plugin-id: rewrite
    }

    logging-plugin {
      plugin-module: logger
      plugin-options: config=/etc/snmpfwd/plugins/logger.conf

      plugin-id: logger
    }


.. _trunking-options-server-chapter:

Trunking options
----------------

Trunk is a persistent TCP connection between SNMP Proxy Forwarder parts
maintained for the purpose of relaying SNMP messages.

.. _trunk-bind-address-server-option:

*trunk-bind-address*
++++++++++++++++++++

Local network endpoint address to bind trunk connection to.

.. _trunk-peer-address-server-option:

*trunk-peer-address*
++++++++++++++++++++

Remote network endpoint address to connect to when establishing trunk connection.

.. _trunk-ping-period-server-option:

*trunk-ping-period*
+++++++++++++++++++

Enables trunk keep alive communication every *N* seconds. Trunk is terminated
and re-established if trunking peer fails to acknowledge the keep alive message
within the *N* seconds time period.

The value of *0* disables trunk keep alive messaging.

.. note::

    Each side of the trunk can monitor trunk connection independently of
    its peer guided by its own *trunk-ping-period* option.

.. _trunk-connection-mode-server-option:

*trunk-connection-mode*
+++++++++++++++++++++++

Trunk connection mode: *client* or *server*. Determines the originator
of the trunk connection. When in *client* mode, actively tries to establish
and maintain running connection with a peer. When in *server* mode, opens
TCP port and listens at it for *client* connections.

.. note::

    There is no correlation between SNMP entity and trunk connection roles.

.. _trunk-crypto-key-server-option:

*trunk-crypto-key*
++++++++++++++++++

Shared secret key used for trunk connection encryption. Missing option disables
trunk encryption.

.. note::

    The key must be the same at both client and server for trunking link
    between them to establish.

.. _trunk-id-server-option:

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

.. _snmp-context-matching-server-chapter:

SNMP context matching
---------------------

.. _snmp-context-engine-id-pattern-server-option:

*snmp-context-engine-id-pattern*
++++++++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by SNMP context engine ID.

.. _snmp-context-name-pattern-server-option:

*snmp-context-name-pattern*
+++++++++++++++++++++++++++

A regular expression matching SNMPv3 messages by SNMP context name.

.. _snmp-context-id-server-option:

*snmp-context-id*
+++++++++++++++++

Unique identifier of a collection of SNMP context configuration options. Used for
matching SNMP context options in inbound SNMP messages
(e.g. `snmp-context-engine-id-pattern-server-option`_,
`snmp-context-name-pattern-server-option`_) for
message routing purposes.

This option can contain :ref:`SNMP macros <snmp-macros>`.

Example:

.. code-block:: bash

    context-group {
      snmp-context-engine-id-pattern: .*?
      snmp-context-name-pattern: .*?

      snmp-context-id: any-context
    }

.. _snmp-pdu-contents-matching-server-chapter:

SNMP PDU contents matching
--------------------------

.. _snmp-pdu-type-pattern-server-option:

*snmp-pdu-type-pattern*
+++++++++++++++++++++++

A regular expression matching SNMPv3 messages by SNMP PDU type.
Recognized PDU types are: *GET*, *SET*, *GETNEXT*, *GETBULK*, *TRAPv1*,
*TRAPv2* (the latter is also applicable for SNMPv3).


.. code-block:: bash

    content-group {
      snmp-pdu-type-pattern: (GET|GETNEXT)
      snmp-content-id: get-content
    }

.. _snmp-pdu-oid-prefix-pattern-list-server-option:

*snmp-pdu-oid-prefix-pattern-list*
++++++++++++++++++++++++++++++++++

List of regular expressions matching OIDs in SNMP PDU var-binds.

.. _snmp-content-id-server-option:

*snmp-content-id*
+++++++++++++++++

Unique identifier of a collection of SNMP content matching options. Used for
matching the contents of inbound SNMP messages (e.g.
`snmp-pdu-type-pattern-server-option`_, `snmp-pdu-oid-prefix-pattern-list-server-option`_) for
message routing purposes.

This option can contain :ref:`SNMP macros <snmp-macros>`.

Example:

.. code-block:: bash

    content-group {
      write-pdu-group {
        snmp-pdu-type-pattern: SET
        snmp-content-id: set-content
      }

      oid-subtree-group {
        snmp-pdu-oid-prefix-pattern-list: 1\.3\.6\.1\.2\.1\.2\..*?
        snmp-content-id: oid-subtree-content
      }

      others {
        snmp-content-id: any-content
      }
    }

.. _network-peers-matching-server-chapter:

Network peers matching
----------------------

.. _snmp-peer-address-pattern-list-server-option:

*snmp-peer-address-pattern-list*
++++++++++++++++++++++++++++++++

List of regular expressions matching source transport endpoints
of SNMP message.

.. _snmp-bind-address-pattern-list-server-option:

*snmp-bind-address-pattern-list*
++++++++++++++++++++++++++++++++

List of regular expressions matching destination transport endpoints
of SNMP message.

.. note::

    If you want to receive SNMP messages at secondary network interfaces
    and be able to match them, make sure you enable the
    `snmp-transport-options-server-option`_ = *virtual-interface*.

.. _snmp-peer-id-server-option:

*snmp-peer-id*
++++++++++++++

Unique identifier matching pairs of source and destination SNMP transport
endpoints. Most importantly, `snmp-bind-address-pattern-list-server-option`_ and
`snmp-peer-address-pattern-list-server-option`_ as well as `snmp-transport-domain-server-option`_.
The *snmp-peer-id* is typically used for message routing purposes.

This option can contain :ref:`SNMP macros <snmp-macros>`.

Example:

.. code-block:: bash

    peers-group {
      snmp-transport-domain: 1.3.6.1.6.1.1.100
      snmp-peer-address-pattern-list: 10\.113\..*?
      snmp-bind-address-pattern-list: 127\.0\.0\.[2-3]:[0-9]+?

      snmp-peer-id: 101
    }

.. _message-routing-server-chapter:

Message routing
---------------

The purpose of these settings is to determine:

* plugin ID to pass SNMP message through
* trunk ID to pass SNMP message to

This is done by searching for a combination of matching IDs.

.. _matching-snmp-context-id-list-server-option:

*matching-snmp-context-id-list*
+++++++++++++++++++++++++++++++

Evaluates to True if incoming SNMP message matches at least one
of `snmp-context-id-server-option`_ in the list.

.. _matching-snmp-content-id-list-server-option:

*matching-snmp-content-id-list*
+++++++++++++++++++++++++++++++

Evaluates to True if incoming SNMP message matches at least one
of `snmp-content-id-server-option`_ in the list.

.. _matching-snmp-credentials-id-list-server-option:

*matching-snmp-credentials-id-list*
+++++++++++++++++++++++++++++++++++

Evaluates to True if `snmp-credentials-id-server-option`_ used for processing incoming
SNMP message is present in the list.

.. _matching-snmp-peer-id-list-server-option:

*matching-snmp-peer-id-list*
++++++++++++++++++++++++++++

Evaluates to True if incoming SNMP message originates from and arrived at
one of the `snmp-peer-id-server-option`_ in the list.

.. _using-plugin-id-list-server-option:

*using-plugin-id-list*
++++++++++++++++++++++

Invoke each of the `plugin-id-server-option`_ in the list in order passing request and response
SNMP PDUs from one :ref:`plugin <plugins>` to the other.

Plugins may modify the message in any way and even block it from further
propagation in which case SNMP message will be dropped.

.. _using-trunk-id-list-server-option:

*using-trunk-id-list*
+++++++++++++++++++++

Unique identifier matching a group of *matching-\** identifiers. Specifically,
these are: `matching-snmp-context-id-list-server-option`_, `matching-snmp-content-id-list-server-option`_,
`matching-snmp-credentials-id-list-server-option`_ and `matching-snmp-peer-id-list-server-option`_.

Incoming (and possibly modified) SNMP message will be forwarded to each
`trunk-id-server-option`_ present in the list.

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
