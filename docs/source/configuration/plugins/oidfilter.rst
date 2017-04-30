
The *oidfilter* plugin
======================

The *oidfilter* plugin is designed to block some of the MIB objects, being served by
the backend SNMP agent, from view of SNMP managers. As easy as it sounds, it is not
actually trivial due to the dynamic nature of SNMP tables and the existence
of *GETNEXT*/*GETBULK* operations supporting them. That explains why configuration
file for *oidfilter* plugin is not just a bunch of regular expression patterns.

Configuration syntax
--------------------

The *oidfilter* plugin configuration file consists of zero or more lines. Each line
has three fields. Each field is an Object Identifier (OID) representing the following
settings

1. An OID **preceding** the allowed OID range. The purpose of this OID is to tell
   SNMP manager for what OID it should send the *GETNEXT* request so that response
   OID would hit this OID range. This *skip* OID may or may not exist at the agent,
   it is only used as a hint to SNMP manager for which OID it should ask next.
2. Start of allowed OID range (inclusive)
3. End of allowed OID range (inclusive)

Each OID in SNMP PDU is tested to fall into *start* .. *end* OID ranges in the order
of their presence in the configuration file. First march terminates the search.
The OID comparison is done by treating OIDs as a sequence of numbers:

.. code-block:: python

    >>> (1, 3, 6) < (1, 3, 7)
    True
    >>> (1, 3, 6) <= (1, 3, 6, 1) <= (1, 3, 7)
    True
    >>> (1, 3, 6) <= (1, 3, 8) <= (1, 3, 7)
    False

The *skip* OID is never used for comparison purposes.

How it works
------------

The *oidfilter* may touch the passing PDU when it goes towards SNMP agent and back. The algorithm
differs depending on the SNMP PDU type.

GET/SET PDU
+++++++++++

When GET or SET PDU is received, the *oidfilter* plugin traverses PDU variables-bindings matching
each request OID against configured OID ranges.

* If no range is matched, such OID is set aside by the *oidproxy* and *NoSuchObject* SNMP error is
  prepared for the upcoming response. Backend SNMP agent will never get queries for that OID.
* If OID range is matched, new request PDU is created and matched OID is put into it.

Once response PDU reaches *oidproxy*, the plugin merges variables-bindings from response PDU
with set aside variables-bindings and sends the combined PDU in response.

GETNEXT PDU
+++++++++++

When GETNEXT is received, the *oidfilter* plugin traverses request PDU variables-bindings
matching each OID against configured OID ranges.

* If request OID precedes the *start* OID in range, the request OID is overwritten by
  the *skip* OID, new request PDU is created and matched OID is put into it.
* If request OID falls into OID range, new request PDU is created and matched OID
  is put into it.
* If no range is matched, such OID is set aside by the *oidproxy* and *EndOfMibView* SNMP error is
  prepared for the upcoming response. Backend SNMP agent will never get queries for that OID.

Once response PDU reaches *oidproxy*, the plugin traverses variables-bindings in response
PDU matching each OID against the OID range that matched the request OID.

* If response OID does not match the OID range which matched the request OID, *oidfilter*
  overrides response OID with the *skip* OID of the next OID range and sets response value
  to *Null*.

Then the plugin merges variables-bindings from response PDU with the variables-bindings set
aside on PDU's way forward and sends the combined PDU in response.

Example configuration
---------------------

The following example whitelists *sysDescr.0* MIB object instance and hints the manager
that it should put *1.3.6.1.2.1.1.1* into *GETNEXT* if they want to hit the *sysDescr.0*
object when walking SNMP agent.

.. code-block:: bash

    # allow sysDescr.0
    1.3.6.1.2.1.1.1 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.1.0

This configuration permits just one columnar object (*IF-MIB::ifDescr.2*) giving
SNMP manager a hint to *GETNEXT 1.3.6.1.2.1.2.2.1.2.1* if they shoot for
*1.3.6.1.2.1.2.2.1.2.2* object.

.. code-block:: bash

    # allow if#2 of ipTable
    1.3.6.1.2.1.2.2.1.2.1 1.3.6.1.2.1.2.2.1.2.2 1.3.6.1.2.1.2.2.1.2.2

To whitelist the whole column of an SNMP table, you should configure the full
range of possible index values. For example, this configuration entry allows
any OID under the *TCP-MIB::tcpConnState* column (*1.3.6.1.2.1.6.13.1.1*)
for as long as it has *127.0.0.1* as its first sub-index.

For range comparison to work, we need to give it a range of sub-OID values past the
*1.3.6.1.2.1.6.13.1.1.127.0.0.1* prefix. From *TCP-MIB::tcpConnectionEntry* we know
that the next index sub-component is port number (*TCP-MIB::tcpConnectionLocalPort*)
so we list its range (0..65535) here.

We also hint SNMP manager to *GETNEXT 1.3.6.1.2.1.6.13.1.1.127.0.0.255.65535*, which
must be the immediate OID preceding the range we allow here, if they want to hit it
when SMMP walking this agent.

.. code-block:: bash

    1.3.6.1.2.1.6.13.1.1.127.0.0.255.65535 1.3.6.1.2.1.6.13.1.1.127.0.0.1.0 1.3.6.1.2.1.6.13.1.1.127.0.0.1.65535

For more information please refer to :doc:`the full configuration example </configuration/examples/command-forwarding-oid-filtering>`.
