
The *rewrite* plugin
====================

The *rewrite* plugin can change SNMP response values into something different by
applying a `regular expression <https://docs.python.org/3/library/re.html#regular-expression-syntax>`_.

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

.. _rewrite-config:

Configuration syntax
--------------------

The *rewrite* plugin configuration file consists of zero or more lines. Each line
has four fields:

1. Regular expression pattern matching OIDs in response PDU
2. Regular expression pattern matching string representation of a value associated with the matched the OID
3. Substitution expression as in `re.sub <https://docs.python.org/3/library/re.html#re.sub>`_
4. Maximum substitutions count (zero disables the limit)

String fields must be quoted (").

For each matching OID in SNMP response PDU, the value is run through substitution function. If
substitution yields empty string, type-specific <empty> value is returned. That can be zero for
integers, empty string for texts and *0.0* for OIDs.

Example configuration
---------------------

The following example appends arbitrary string to whatever value is returned for
*SNMPv2-MIB::sysDescr.0*:

.. code-block:: bash

    "^1\.3\.6\.1\.2\.1\.1\.1\.0$" "(.*)" "\\1 (SNMP Proxy is watching you)" 0

This snippet resets values for all *SNMPv2-MIB::system* OIDs:

.. code-block:: bash

    "^1\.3\.6\.1\.2\.1\.1.*$" ".*" "" 0

For more information please refer to :doc:`the full configuration example </configuration/examples/command-forwarding-rewriting-response>`.
