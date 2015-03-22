# SNMP Forwarder plugin module
import re
import sys
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import msg
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'
apiVersions = 0, 1

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

moduleOptions = moduleOptions.split('=')
if moduleOptions[0] == 'config':
    try:
        for l in open(moduleOptions[1]).readlines():
            l = l.strip()
            if not l or l[0] == '#':
                continue
            try:
                k, v = l.split(' ', 1)
            except ValueError:
                k, v = l, ''

            msg('rewrite: %s -> %s' % (k, v or '<nullify>'))

            rewriteList.append((re.compile(k), v))
    except:
        raise SnmpfwdError('rewrite: config file load failure: %s' % sys.exc_info()[1])

msg('rewrite: plugin initialization complete')

def processCommandResponse(pluginId, snmpEngine, pdu, **context):
    varBinds = []
    for oid, val in v2c.apiPDU.getVarBinds(pdu):
        for pat, newVal in rewriteList:
            if pat.match(str(oid)):
                if not newVal:
                    newVal = nullifyMap.get(val.tagSet, newVal)
                val = val.clone(newVal)
                break
        varBinds.append((oid, val))
    v2c.apiPDU.setVarBinds(pdu, varBinds)
    return status.NEXT, pdu
