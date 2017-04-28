#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#
# SNMP Proxy Forwarder plugin module
#
import re
import sys
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import msg
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'
apiVersions = 0, 2

PASS, BLOCK = 0, 1

PLUGIN_NAME = 'oidfilter'

commands = {
    'pass': PASS,
    'block': BLOCK
}

oidsList = []

moduleOptions = moduleOptions.split('=')

if moduleOptions[0] == 'config':
    try:
        for line in open(moduleOptions[1]).readlines():
            line = line.strip()
            if not line or line[0] == '#':
                continue
            try:
                k, v = line.split()

            except ValueError:
                k, v = line, PASS

            else:
                try:
                    v = commands[v]

                except KeyError:
                    raise SnmpfwdError('%s: unknown  configuration instruction: %s', (PLUGIN_NAME, v))

            msg('%s: %s -> %s' % (PLUGIN_NAME, k, v))

            oidsList.append((re.compile(k), v))

    except Exception:
        raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, sys.exc_info()[1]))

msg('%s: plugin initialization complete' % PLUGIN_NAME)


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet not in (v2c.GetRequestPDU.tagSet, v2c.SetRequestPDU.tagSet):
        return status.NEXT, pdu

    reqVarBinds = v2c.VarBindList()
    rspVarBinds = []

    for varBind in pdu[3]:
        oid = str(varBind[0])
        for pat, decision in oidsList:
            if pat.match(oid):
                if decision == PASS:
                    reqVarBinds.append(varBind)
                    rspVarBinds.append(None)
                elif decision == BLOCK:
                    v2c.apiVarBind.setOIDVal(varBind, (varBind[0], v2c.NoSuchObject('')))
                    rspVarBinds.append(varBind)
                break
        else:
            reqVarBinds.append(varBind)
            rspVarBinds.append(None)

    if not reqVarBinds:
        pdu = v2c.apiPDU.getResponse(pdu)
        reqVarBinds.extend(rspVarBinds)
        nextAction = status.RESPOND
    else:
        reqCtx['setaside-oids'] = rspVarBinds
        nextAction = status.NEXT

    v2c.apiPDU.setVarBindList(pdu, reqVarBinds)

    return nextAction, pdu


def processCommandResponse(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet != v2c.GetResponsePDU.tagSet:
        return status.NEXT, pdu

    varBinds = v2c.VarBindList()

    rspVarBinds = pdu[3]
    reqVarBinds = reqCtx.pop('setaside-oids')

    for idx, varBind in enumerate(reqVarBinds):
        if varBind:
            varBinds.append(varBind)
        else:
            try:
                varBinds.append(rspVarBinds[idx])

            except IndexError:
                msg('%s: missing response OID #%s' % (PLUGIN_NAME, idx))
                return status.DROP, pdu

    v2c.apiPDU.setVarBindList(pdu, varBinds)

    return status.NEXT, pdu


def processNotificationRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet not in (v2c.SNMPv2TrapPDU.tagSet, v2c.InformRequestPDU.tagSet):
        return status.NEXT, pdu

    varBinds = v2c.VarBindList()

    for varBind in pdu[3]:
        oid = str(varBind[0])
        for pat, decision in oidsList:
            if pat.match(oid):
                if decision == PASS:
                    varBinds.append(varBind)
                break
        else:
            varBinds.append(varBind)

    if not varBinds:
        return status.DROP, pdu

    pdu.getComponentByPosition(3, varBinds, verifyConstraints=False, matchTags=False, matchConstraints=False)

    return status.NEXT, pdu
