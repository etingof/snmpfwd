#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#

class SnmpfwdError(Exception):
    pass


class EofError(SnmpfwdError):
    pass
