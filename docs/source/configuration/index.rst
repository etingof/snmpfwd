
System configuration
====================

This documents describes server configuration file.

The configuration file is composed of a set of option/value pairs possibly
enclosed into blocks. Blocks provide lexical scopes for options. Blocks names
have no pre-defined meaning and serve as hints to a human reader.

Options are distinguished from values by trailing colon (:). There may be
several whitespace-separated values assigned to option.

For example:

.. code-block:: bash

    test-option: global-default-value

    outermost-block
    {
        test-option: a-bit-more-specific-value

        more-specific-block
        {
            test-option: specific-value

            very-concrete-settings
            {
                test-option: highly-specific-value
            }
        }
    }

Evaluating the above configuration for *test-option* would yield:

.. code-block:: bash

    READ .test-option -> global-default-value
    READ .outermost-block.test-option -> a-bit-more-specific-value
    READ .outermost-block.more-specific-block.test-option -> specific-value
    READ .outermost-block.more-specific-block.test-option.very-concrete-settings.test-option -> highly-specific-value

Options specified inside a block apply to their current scopes as
well as to all nested scopes unless the same option exists there:

.. code-block:: bash

    outermost-block
    {
        test-option: test-value

        more-specific-block
        {
        }
    }

Evaluating the above configuration for *test-option* would yield:

.. code-block:: bash

    READ .test-option -> ERROR
    READ .outermost-block.test-option -> test-value
    READ .outermost-block.more-specific-block.test-option -> test-value

Configuration files
-------------------

Server and client parts of the system consume their own configuration file.
Many options are applicable to both client and server, though some options
are specific to either parts of the system.

Some of the options only make sense inside a block while some can only be of
global scope.

.. toctree::
   :maxdepth: 2

   server-configuration
   client-configuration
   macro

.. _plugins:

Plugins
-------

Both :ref:`client <plugin-options-client-chapter>` and
:ref:`server <plugin-options-server-chapter>` parts of SNMP Proxy Forwarder
can be configured to pass PDUs through a chain of plugin modules.
A plugin module can modify or replace passing PDU or take any other
action of its choice.

Each plugin module is a Python code snippet executing within the
context of a single SNMP query and exposing a few entry points for
the server or client parts of SNMP Proxy Forwarder to invoke it at
the key points of SNMP PDU processing.

You can run the same or different plugin modules at both client
and server. The choice of plugin runner probably depends on the
system architecture, load distribution and security considerations.

.. toctree::
   :maxdepth: 2
   :glob:

   plugins/*

Examples
--------

.. toctree::
   :maxdepth: 2
   :glob:

   examples/*
