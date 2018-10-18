#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import re
import socket

from snmpfwd.error import SnmpfwdError


IP_TEMPLATES = [
    (socket.AF_INET, r'^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$|^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$')
]

if socket.has_ipv6:
    IP_TEMPLATES.append(
        (socket.AF_INET6, r'^\[([0-9:]+?)\]:([0-9]+)$|^\[([0-9:]+?)\]$')
    )


def parseTrunkEndpoint(address, defaultPort=0):

    for af, pattern in IP_TEMPLATES:

        hp = re.split(pattern, address, maxsplit=1)
        if len(hp) == 5:
            if hp[1]:
                h, p = hp[1:3]

            elif hp[3]:
                h, p = hp[3], defaultPort

            else:
                continue

            try:
                p = int(p)

            except (ValueError, IndexError):
                raise SnmpfwdError('bad port specification: %s' % (address,))

            return af, h, p

    raise SnmpfwdError('bad address specification: %s' % (address,))
