#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
# SNMP Proxy Forwarder plugin module
#
import re
import sys
import shlex
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import debug, info, error
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'

apiVersions = 0, 2

PLUGIN_NAME = 'rewrite'

# This map represents an "empty" value per SNMP type
nullifyMap = {
    v2c.ObjectIdentifier.tagSet: '0.0',
    v2c.Integer.tagSet: 0,
    v2c.Integer32.tagSet: 0,
    v2c.OctetString.tagSet: '',
    v2c.IpAddress.tagSet: '0.0.0.0',
    v2c.Counter32.tagSet: 0,
    v2c.Gauge32.tagSet: 0,
    v2c.Unsigned32.tagSet: 0,
    v2c.TimeTicks.tagSet: 0,
    v2c.Opaque.tagSet: '',
    v2c.Counter64.tagSet: 0
}

rewriteList = []

for moduleOption in moduleOptions:

    optionName, optionValue = moduleOption.split('=', 1)

    if optionName == 'config':

        try:
            configFile = optionValue

            for lineNo, line in enumerate(open(configFile).readlines()):
                line = line.strip()

                if not line or line.startswith('#'):
                    continue

                try:
                    oidPatt, valPatt, valRepl, replCount = shlex.split(line)

                except ValueError:
                    raise SnmpfwdError('%s: syntax error at %s:%d: %s' % (PLUGIN_NAME, configFile, lineNo + 1, sys.exc_info()[1]))

                debug('%s: for OIDs like "%s" and values matching "%s" rewrite value into "%s" (max %s times)' % (PLUGIN_NAME, oidPatt, valPatt, valRepl, replCount))

                rewriteList.append((re.compile(oidPatt), re.compile(valPatt), valRepl, int(replCount)))

        except Exception:
            raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, sys.exc_info()[1]))

info('%s: plugin initialization complete' % PLUGIN_NAME)


def processCommandResponse(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):
    varBinds = []

    for oid, val in v2c.apiPDU.getVarBinds(pdu):
        for oidPatt, valPatt, valRepl, replCount in rewriteList:
            if oidPatt.match(str(oid)):
                newVal = valPatt.sub(valRepl, str(val), replCount)
                if not newVal:
                    newVal = nullifyMap.get(val.tagSet, v2c.Null())
                val = val.clone(newVal)
                break

        varBinds.append((oid, val))

    v2c.apiPDU.setVarBinds(pdu, varBinds)

    return status.NEXT, pdu

processNotificationRequest = processCommandResponse
