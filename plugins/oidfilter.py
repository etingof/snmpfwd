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

oidsList = []

moduleOptions = moduleOptions.split('=')

if moduleOptions[0] == 'config':
    try:
        configFile = moduleOptions[1]

        for line in open(configFile).readlines():
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            try:
                skip, begin, end = line.split()

            except ValueError:
                raise SnmpfwdError('%s: bad configuration syntax: "%s"' % (PLUGIN_NAME, line))

            try:
                skip = v2c.ObjectIdentifier(skip)
                begin = v2c.ObjectIdentifier(begin)
                end = v2c.ObjectIdentifier(end)

            except Exception:
                raise SnmpfwdError('%s: malformed OID %s/%s/%s' % (PLUGIN_NAME, skip, begin, end))

            oidsList.append((skip, begin, end))

            oidsList.sort(key=lambda x: x[0])

            skipOids = [x[0] for x in oidsList]

            if len(set(skipOids)) != len(skipOids):
                raise SnmpfwdError('%s: duplicate skip OIDs in %s: %s' % (PLUGIN_NAME, configFile, ', '.join(set([str(x) for x in skipOids if skipOids.count(x) > 1]))))

        for skip, begin, end in oidsList:
            msg('%s: skip to %s allow from %s to %s' % (PLUGIN_NAME, skip, begin, end))

    except Exception:
        raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, sys.exc_info()[1]))

msg('%s: plugin initialization complete' % PLUGIN_NAME)

noSuchObject = v2c.NoSuchObject('')
endOfMibVew = v2c.EndOfMibView('')


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):

    reqVarBinds = v2c.VarBindList()
    rspVarBinds = []

    if pdu.tagSet in (v2c.GetRequestPDU.tagSet, v2c.SetRequestPDU.tagSet):

        for varBind in v2c.apiTrapPDU.getVarBindList(pdu):
            oid, val = v2c.apiVarBind.getOIDVal(varBind)
            for skip, begin, end in oidsList:
                if begin <= oid <= end:
                    break
            else:
                val = None

            if val is None:
                v2c.apiVarBind.setOIDVal(varBind, (oid, noSuchObject))
                rspVarBinds.append(varBind)
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

    elif pdu.tagSet == v2c.GetNextRequestPDU.tagSet:

        reqAclIndices = []

        for varBind in v2c.apiTrapPDU.getVarBindList(pdu):
            oid, val = v2c.apiVarBind.getOIDVal(varBind)
            for idx, (skip, begin, end) in enumerate(oidsList):
                # OID preceding range
                if oid < begin:
                    # OID allowed, fast-forward to the start of this range
                    oid = skip
                    reqAclIndices.append(idx)
                    break

                # response will get out of range - skip to the next range
                elif oid == end:
                    continue

                # OID in range
                elif begin <= oid <= end:
                    # OID allowed, pass as-is
                    reqAclIndices.append(idx)
                    break
            else:
                # non-matching OIDs -- block
                val = None
                reqAclIndices.append(None)

            if val is None:
                v2c.apiVarBind.setOIDVal(varBind, (oid, endOfMibVew))
                rspVarBinds.append(varBind)
            else:
                v2c.apiVarBind.setOIDVal(varBind, (oid, val))
                reqVarBinds.append(varBind)
                rspVarBinds.append(None)

        if reqVarBinds:
            reqCtx['setaside-oids'] = rspVarBinds
            reqCtx['varbind-acls'] = reqAclIndices
            nextAction = status.NEXT
        else:
            pdu = v2c.apiPDU.getResponse(pdu)
            reqVarBinds.extend(rspVarBinds)
            nextAction = status.RESPOND

        v2c.apiPDU.setVarBindList(pdu, reqVarBinds)

        return nextAction, pdu

    elif pdu.tagSet == v2c.GetBulkRequestPDU.tagSet:
        # TODO: GETBULK handling needs to be implemented
        return status.DROP, pdu

    else:
        return status.NEXT, pdu


def processCommandResponse(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet != v2c.GetResponsePDU.tagSet:
        return status.NEXT, pdu

    if 'setaside-oids' not in reqCtx:
        return status.NEXT, pdu

    varBinds = v2c.VarBindList()

    rspVarBinds = v2c.apiPDU.getVarBindList(pdu)
    reqVarBinds = reqCtx['setaside-oids']

    oidsListIndices = reqCtx.get('varbind-acls', ())

    rspIdx = idx = 0

    for varBind in reqVarBinds:
        if varBind is None:
            try:
                varBind = rspVarBinds[rspIdx]

            except IndexError:
                msg('%s: missing response OID #%s' % (PLUGIN_NAME, rspIdx))
                return status.DROP, pdu

            else:
                rspIdx += 1

            # catch leaking response OIDs
            if oidsListIndices:
                oidsListIdx = oidsListIndices[idx]

                skip, begin, end = oidsList[oidsListIdx]

                if not (begin <= varBind[0] <= end):
                    oidsListIdx += 1

                    if len(oidsList) == oidsListIdx:
                        v2c.apiVarBind.setOIDVal(varBind, (end, endOfMibVew))
                    else:
                        skip, begin, end = oidsList[oidsListIdx]
                        v2c.apiVarBind.setOIDVal(varBind, (skip, v2c.Null()))

        varBinds.append(varBind)

        idx += 1

    v2c.apiPDU.setVarBindList(pdu, varBinds)

    return status.NEXT, pdu


def processNotificationRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet not in (v2c.SNMPv2TrapPDU.tagSet, v2c.InformRequestPDU.tagSet):
        return status.NEXT, pdu

    varBinds = v2c.VarBindList()

    for varBind in v2c.apiTrapPDU.getVarBindList(pdu):
        oid = varBind[0]
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
