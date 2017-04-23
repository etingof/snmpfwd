
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

Configuration syntax
--------------------

Server and client parts of the system consume their own configuration file.
Many options are applicable to both client and server, though some options
are specific to either parts of the system.

Some of the options only make sense inside a block while some can only be of
global scope.

.. toctree::
   :maxdepth: 2

   server-configuration
   client-configuration

Examples
--------

.. toctree::
   :maxdepth: 2
   :glob:

   examples/*
