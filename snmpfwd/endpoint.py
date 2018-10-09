#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import re

from snmpfwd.error import SnmpfwdError

from pysnmp.carrier.asynsock.dgram import udp
try:
    from pysnmp.carrier.asynsock.dgram import udp6
except ImportError:
    udp6 = None


def parseTransportAddress(transportDomain, transportAddress, transportOptions, defaultPort=0):
    if (('transparent-proxy' in transportOptions or
         'virtual-interface' in transportOptions) and '$' in transportAddress):
        addrMacro = transportAddress

        if transportDomain[:len(udp.domainName)] == udp.domainName:
            h, p = '0.0.0.0', defaultPort
        else:
            h, p = '::0', defaultPort

    else:
        addrMacro = None

        if transportDomain[:len(udp.domainName)] == udp.domainName:
            if ':' in transportAddress:
                h, p = transportAddress.split(':', 1)
            else:
                h, p = transportAddress, defaultPort
        else:
            hp = re.split(r'^\[(.*?)\]:([0-9]+)', transportAddress, maxsplit=1)
            if len(hp) != 4:
                raise SnmpfwdError('bad address specification')

            h, p = hp[1:3]

        try:
            p = int(p)

        except (ValueError, IndexError):
            raise SnmpfwdError('bad port specification')

    return (h, p), addrMacro
