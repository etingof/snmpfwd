
System configuration
====================

The SNMP Proxy Forwarder system consists of two daemons - client and server. Each
accepts a few command-line options and configuration files.

.. _cli_options:

Command-line options
--------------------

Client and server daemons share the same set of command-line options:

.. code-block:: bash

    $ snmpfwd-server.py --help
    Usage: snmpfwd-server.py
        [--help]
        [--version]
        [--debug-snmp=<options>]
        [--debug-asn1=<options>]
        [--daemonize]
        [--process-user=<uname>] [--process-group=<gname>]
        [--pid-file=<file>]
        [--logging-method=<options>]
        [--log-level=<options>]
        [--config-file=<file>]


.. _debug_snmp_cli_option:

**--debug-snmp**
++++++++++++++++

The *--debug-snmp* option makes the daemon emitting detailed log of SNMP protocol
related debugging. Debugging can be enabled for all or for just some of the SNMP
engine subsystems by adding their names to the *--debug-snmp* option.

Recognized SNMP debugging options include:

* *io* -- report raw network traffic
* *msgproc* -- report SNMP message processing
* *secmod* -- report SNMP security module operations
* *mibbuild* -- report on MIB loading and processing
* *mibinstrum* -- report agent MIB operatrions
* *acl* -- report MIB access access control operations
* *proxy* -- report on SNMP version translation operations
* *app* -- application-specific debugging
* *all* -- enable full SNMP debugging

SNMP debugging is fully disabled by default.

.. _debug_asn1_cli_option:

**--debug-asn1**
++++++++++++++++

SNMP is backed by the `ASN.1 <https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One>`_
for data representation. The *--debug-asn1* option makes the daemon emitting detailed log
of ASN.1 data de/serialization. Debugging can be enabled for either encoder or decoder,
or for everything ASN.1 related by adding their names to the *--debug-asn1* option.

Recognized ASN.1 debugging options include:

* *encoder* -- debug data serialization
* *decoder* -- debug data deserialization
* *all* -- enable full ASN.1 debugging

ASN.1 debugging is fully disabled by default.

.. _daemonize_cli_option:

**--daemonize**
+++++++++++++++

Unless *--daemonize* option is given, the daemon will remain an interactive process.
With the *-daemonize* option, the daemon will detach itself from user terminal,
close down standard I/O streams etc.

.. _process_user_cli_option:
.. _process_group_cli_option:

**--process-user** & **--process-group**
++++++++++++++++++++++++++++++++++++++++

It is generally safer to run daemons under a non-privileged user. However, it may
be necessary to, at least, start SNMP Proxy Forwarder parts as root to let
the process bind to privileged ports (161/udp for SNMP by default).

In this case it may make sense to drop process privileges upon initialization
by becoming *--process-user* belonging to *--process-group*.

.. _pid_file_cli_option:

**--pid-file**
++++++++++++++

Especially when running in *--daemonize** mode, it might be handy to keep
track of UNIX process ID allocated to the running daemon. Primarily, this
can be used for killing or restarting the process.

The *--pid-file** option can be used to specify a disk file where daemon
would store its PID.

.. _logging_method_cli_option:

**--logging-method**
++++++++++++++++++++

SNMP Proxy Forwarder daemons can log using one of the following methods.
The default is *stderr*.

**--logging-method=syslog**
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The *syslog* logging method requires the following sub-options:

.. code-block:: bash

    --logging-method=syslog:facility[:priority[:dest[:port:[tcp|udp]]]]

Where:

* *facility* -- one of the recognized syslog service `facilities <https://en.wikipedia.org/wiki/Syslog#Facility>`_
* *priority* -- one of recognized syslog service `priorities <https://en.wikipedia.org/wiki/Syslog#Severity_level>`_ (optional)
* *dest* -- can be either an absolute path to a local socket or network address where syslog service is listening (optional)
* *port* -- if network address of the syslog service is used for *dest*, *port* be a TCP or UDP port number (optional)
* *tcp* or *udp* -- TCP or UDP network protocol to use (optional)

**--logging-method=file**
~~~~~~~~~~~~~~~~~~~~~~~~~

The *file* logging method redirects daemon logging into a local file. The log file
could be made automatically rotated based on time or size criteria.

The following sub-options are supported:

.. code-block:: bash

    --logging-method=file:path[:criterion]

Where:

* *path* -- path to a log file
* *criterion* -- should consist of a number followed by one of the specifiers:

  - *k* -- rotate when file size exceeds N kilobytes
  - *m* -- rotate when file size exceeds N megabytes
  - *g* -- rotate when file size exceeds N gigabytes
  - *S* -- rotate when file age exceeds N seconds
  - *M* -- rotate when file age exceeds N minutes
  - *H* -- rotate when file age exceeds N hours
  - *D* -- rotate when file age exceeds N days

**--logging-method=stdout/stderr**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When *stdout* or *stderr* logging methods are used, daemon log messages are directed
to either process standard output or standard error stream.

**--logging-method=null**
~~~~~~~~~~~~~~~~~~~~~~~~~

The *null* logging method completely inhibits all daemon logging.

.. _log_level_cli_option:

**--log-level**
+++++++++++++++

The *--log-level* option limits the minimum severity of the log messages
to actually log.

Recognized log levels are:

* *debug* -- log at all levels
* *info* - log informational and error messages only
* *error* - log error messages only

.. _config_file_cli_option:

**--config-file**
+++++++++++++++++

The *--config-file* option specifies path to daemon `configuration file <configuration_files>`_.

.. _configuration_files:

Configuration files
-------------------

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
