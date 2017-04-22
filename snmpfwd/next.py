#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#


class Numbers(object):
    current = 0

    def getId(self):
        self.current += 1
        if self.current > 65535:
            self.current = 0
        return self.current

numbers = Numbers()

getId = numbers.getId
