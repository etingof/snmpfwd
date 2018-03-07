#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#


def expandMacro(option, context):
    for k in context:
        pat = '${%s}' % k
        if option and '${' in option:
            option = option.replace(pat, str(context[k]))
    return option


def expandMacros(options, context):
    options = list(options)
    for idx, option in enumerate(options):
        options[idx] = expandMacro(option, context)
    return options
