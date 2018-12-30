#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#

class SnmpfwdError(Exception):
    pass


class EofError(SnmpfwdError):
    pass
