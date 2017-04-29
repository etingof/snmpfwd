#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#
# SNMP Proxy Forwarder plugin module
#
import sys
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import msg
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'
apiVersions = 0, 2

BLOCK, PASS = 0, 1

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

            if not line or line.startswith('#'):
                continue

            try:
                begin, end, decision = line.split()

            except ValueError:
                raise SnmpfwdError('%s: bad configuration syntax: "%s"' % (PLUGIN_NAME, line))

            try:
                begin = tuple(v2c.ObjectIdentifier(begin))
                end = tuple(v2c.ObjectIdentifier(end))

            except Exception:
                raise SnmpfwdError('%s: malformed OID %s/%s' % (PLUGIN_NAME, begin, end))

            try:
                decision = commands[decision]

            except KeyError:
                raise SnmpfwdError('%s: unknown  configuration instruction: %s' % (PLUGIN_NAME, decision))

            msg('%s: %s .. %s -> %s' % (PLUGIN_NAME, v2c.ObjectIdentifier(begin), v2c.ObjectIdentifier(end), decision == PASS and 'PASS' or 'BLOCK'))

            oidsList.append((begin, end, decision))

    except Exception:
        raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, sys.exc_info()[1]))

msg('%s: plugin initialization complete' % PLUGIN_NAME)


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet not in (v2c.GetRequestPDU.tagSet, v2c.SetRequestPDU.tagSet):
        return status.NEXT, pdu

    reqVarBinds = v2c.VarBindList()
    rspVarBinds = []

    for varBind in pdu[3]:
        oid = tuple(varBind[0])
        for begin, end, decision in oidsList:
            if begin <= oid <= end:
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

    if reqVarBinds:
        reqCtx['setaside-oids'] = rspVarBinds
        nextAction = status.NEXT
    else:
        pdu = v2c.apiPDU.getResponse(pdu)
        reqVarBinds.extend(rspVarBinds)
        nextAction = status.RESPOND

    v2c.apiPDU.setVarBindList(pdu, reqVarBinds)

    return nextAction, pdu


def processCommandResponse(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet != v2c.GetResponsePDU.tagSet:
        return status.NEXT, pdu

    varBinds = v2c.VarBindList()

    rspVarBinds = v2c.apiPDU.getVarBindList(pdu)
    reqVarBinds = reqCtx.pop('setaside-oids')

    idx = 0

    for varBind in reqVarBinds:
        if varBind:
            varBinds.append(varBind)
        else:
            try:
                varBinds.append(rspVarBinds[idx])

            except IndexError:
                msg('%s: missing response OID #%s' % (PLUGIN_NAME, idx))
                return status.DROP, pdu
            else:
                idx += 1

    v2c.apiPDU.setVarBindList(pdu, varBinds)

    return status.NEXT, pdu


def processNotificationRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet not in (v2c.SNMPv2TrapPDU.tagSet, v2c.InformRequestPDU.tagSet):
        return status.NEXT, pdu

    varBinds = v2c.VarBindList()

    for varBind in v2c.apiTrapPDU.getVarBindList(pdu):
        oid = tuple(varBind[0])
        for begin, end, decision in oidsList:
            if begin <= oid <= end:
                if decision == PASS:
                    varBinds.append(varBind)
                break
        else:
            varBinds.append(varBind)

    if not varBinds:
        return status.DROP, pdu

    v2c.apiPDU.setVarBindList(pdu, varBinds)

    return status.NEXT, pdu
