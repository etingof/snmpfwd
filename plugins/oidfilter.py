#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#
# SNMP Proxy Forwarder plugin module
#
import sys
import bisect
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import debug, info, error
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'

apiVersions = 0, 2

BLOCK, PASS = 0, 1

PLUGIN_NAME = 'oidfilter'

oidsList = []
endOids = []

logDenials = False

for moduleOption in moduleOptions:

    optionName, optionValue = moduleOption.split('=', 1)

    if optionName == 'config':
        try:
            configFile = optionValue

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

            idx = 0
            while idx < len(oidsList):
                skip, begin, end = oidsList[idx]
                if skip >= begin:
                    raise SnmpfwdError('%s: skip OID %s >= begin OID %s at %s' % (PLUGIN_NAME, skip, begin, configFile))
                if end < begin:
                    raise SnmpfwdError('%s: end OID %s < begin OID %s at %s' % (PLUGIN_NAME, end, begin, configFile))
                if idx:
                    prev_skip, prev_begin, prev_end = oidsList[idx - 1]
                    if skip <= prev_skip:
                        raise SnmpfwdError('%s: skip OID %s not increasing at %s' % (PLUGIN_NAME, skip, configFile))
                    if begin <= prev_begin:
                        raise SnmpfwdError('%s: begin OID %s not increasing at %s' % (PLUGIN_NAME, begin, configFile))
                    if end <= prev_end:
                        raise SnmpfwdError('%s: end OID %s not increasing at %s' % (PLUGIN_NAME, end, configFile))
                    if begin < prev_end:
                        raise SnmpfwdError('%s: non-adjacent end OID %s followed by begin OID %s at %s' % (PLUGIN_NAME, prev_end, begin, configFile))

                idx += 1

                debug('%s: #%d skip to %s allow from %s to %s' % (PLUGIN_NAME, idx, skip, begin, end))

            # cast to built-in tuple type for better comparison performance down the road
            oidsList = [(tuple(skip), tuple(begin), tuple(end)) for skip, begin, end in oidsList]

            # we use this for pivoting dichotomy search
            endOids = [x[2] for x in oidsList]

        except Exception:
            raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, sys.exc_info()[1]))

    elif optionName == 'log-denials':
        logDenials = optionValue == 'true'
        info('%s: will log denied OIDs' % PLUGIN_NAME)

info('%s: plugin initialization complete' % PLUGIN_NAME)

noSuchObject = v2c.NoSuchObject('')
endOfMibVew = v2c.EndOfMibView('')


def formatDenialMsg(pdu, snmpReqInfo):
    denialMsg = '%s: %s' % (PLUGIN_NAME, pdu.__class__.__name__)
    denialMsg += ' from %s:%s' % (snmpReqInfo['snmp-peer-address'], snmpReqInfo['snmp-peer-port'])
    denialMsg += ' at %s:%s' % (snmpReqInfo['snmp-bind-address'], snmpReqInfo['snmp-bind-port'])
    denialMsg += ' snmp-credentials-id %s' % snmpReqInfo['server-snmp-credentials-id']
    return denialMsg


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):

    reqVarBinds = v2c.VarBindList()
    rspVarBinds = []

    if pdu.tagSet in (v2c.GetRequestPDU.tagSet, v2c.SetRequestPDU.tagSet):

        deniedOids = []

        for varBind in v2c.apiTrapPDU.getVarBindList(pdu):
            oid, val = v2c.apiVarBind.getOIDVal(varBind)
            oid = tuple(oid)
            idx = bisect.bisect_left(endOids, oid)
            while idx < len(endOids):
                skip, begin, end = oidsList[idx]
                if begin <= oid <= end:
                    break
                elif oid > end:
                    val = None
                    break
                idx += 1
            else:
                val = None

            if val is None:
                # pretend no such OID exists even without asking the backend
                v2c.apiVarBind.setOIDVal(varBind, (oid, noSuchObject))
                rspVarBinds.append(varBind)

                # report OIDs we are sending errors for
                if logDenials:
                    deniedOids.append(str(varBind[0]))
            else:
                reqVarBinds.append(varBind)
                rspVarBinds.append(None)

        if logDenials and deniedOids:
            denialMsg = formatDenialMsg(pdu, snmpReqInfo)
            denialMsg += ' OIDs ' + ', '.join(deniedOids)
            denialMsg += ' denied'
            error(denialMsg)

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
        skippedOids = []

        for varBind in v2c.apiTrapPDU.getVarBindList(pdu):
            hitEndOfRange = False

            oid, val = v2c.apiVarBind.getOIDVal(varBind)
            oid = tuple(oid)
            idx = bisect.bisect_left(endOids, oid)

            while idx < len(endOids):
                skip, begin, end = oidsList[idx]

                # OID preceding range
                if oid < begin:
                    # report only completely out-of-ranges OIDs
                    if logDenials and not hitEndOfRange and oid != skip:
                        skippedOids.append((oid, skip))

                    # OID allowed, fast-forward to the start of this range
                    oid = skip
                    reqAclIndices.append(idx)
                    break

                # response will get out of range - skip to the next range
                elif oid == end:
                    hitEndOfRange = True
                    idx += 1
                    continue

                # OID in range
                elif begin <= oid <= end:
                    # OID allowed, pass as-is
                    reqAclIndices.append(idx)
                    break

                else:
                    idx += 1
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

        if logDenials and skippedOids:
            denialMsg = formatDenialMsg(pdu, snmpReqInfo)
            denialMsg += ' ' + ', '.join(['%s not in range skipping to %s' % (v2c.ObjectIdentifier(x[0]), v2c.ObjectIdentifier(x[1])) for x in skippedOids])
            info(denialMsg)

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
                error('%s: missing response OID #%s' % (PLUGIN_NAME, rspIdx))
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
        oid, val = varBind
        oid = tuple(oid)
        idx = bisect.bisect_left(endOids, oid)
        while idx < len(endOids):
            skip, begin, end = oidsList[idx]
            if begin <= oid <= end:
                break
            elif oid > end:
                val = None
                break
            idx += 1
        else:
            val = None

        if val is not None:
            varBinds.append(varBind)

    if not varBinds:
        return status.DROP, pdu

    v2c.apiPDU.setVarBindList(pdu, varBinds)

    return status.NEXT, pdu
