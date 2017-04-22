#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#


def expandMacros(s, d):
    for k in d:
        if not s or '${' not in s:
            return s
        pat = '${%s}' % k
        s = s.replace(pat, str(d[k]))
    return s
