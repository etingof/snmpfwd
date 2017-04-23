
SNMP Proxy Forwarder
====================

The SNMP Proxy forwarder tool works as an application-level SNMP proxy
logically split onto two parts: server and client. The server part
acts as SNMP agent while the client part is SNMP manager. These
parts maintain persistent, authenticated and encrypted connections with
each other for the purpose of passing SNMP messages back and forth.

Server and client parts may reside at different networks thus improving
security and network isolation.

Depending on the network topology and goals one could run multiple instances
of server and/or client parts of the system. Servers and clients may thus
build a network of server/client nodes passing SNMP messages to each other
achieving better reliability, performance and security.

Both server and client parts can be configured to route SNMP messages
based on virtually any SNMP message property. For instance, server part
may chose to route SNMP messages to clients residing at different networks
depending on specific OID being present in the message. Or client part can
chose SNMP agent to forward SNMP message to depending on the original
destination address at which server part received SNMP message in the
first place.

Besides SNMP message routing, server part can modify SNMP messages
before passing them on to clients. Changes may apply to both incoming
and outgoing SNMP messages. The logic powering SNMP message modification
can be expressed in form of isolated `Python <http://www.python.org>`_
snippets called *plugins*. Users can implement their own plugins and let
server part of SNMP proxy forwarder calling them.

Configuration
-------------

The system is driven by configuration files. Depending on the desired system's
configuraton, the complexity of configuration files can vary. We maintain a
collection of use-cases and example configurations implementing them.

.. toctree::
   :maxdepth: 2

   /configuration/index

Installation
------------

The easiest way to download and install SNMP forwarder is via Python `pip` tool:

.. code-block:: bash

   # pip install snmpfwd

Alternatively, you could download source code from
`GitHub repo <https://github.com/etingof/snmpfwd/releases>`_ and install is manually.

Changes
-------

.. toctree::
   :maxdepth: 1

   /changelog

License
-------

.. toctree::
   :maxdepth: 2

   /license

Contact
-------

If something does not work as expected,
`open an issue <https://github.com/etingof/snmpfwd/issues>`_
at GitHub or post your question
`on Stack Overflow <http://stackoverflow.com/questions/ask>`_
or try browsing snmpfwd-users
`mailing list archives <https://sourceforge.net/p/snmpfwd/mailman/snmpfwd-users/>`_.
