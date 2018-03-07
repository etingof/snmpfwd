#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
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

null = v2c.Null()
noSuchInstance = v2c.NoSuchInstance()
endOfMibView = v2c.EndOfMibView()


def formatDenialMsg(pdu, trunkMsg):
    denialMsg = '%s: callflow-id %s %s' % (PLUGIN_NAME, trunkMsg['callflow-id'], pdu.__class__.__name__)
    denialMsg += ' from %s:%s' % (trunkMsg['snmp-peer-address'], trunkMsg['snmp-peer-port'])
    denialMsg += ' at %s:%s' % (trunkMsg['snmp-bind-address'], trunkMsg['snmp-bind-port'])
    return denialMsg


def findAcl(oid, nextOid=False):
    aclIdx = bisect.bisect_left(endOids, oid)

    while aclIdx < len(endOids):

        skip, begin, end = oidsList[aclIdx]

        # OID preceding range
        if nextOid and oid < begin:
            # OID allowed, fast-forward to the start of this range
            return skip, aclIdx

        # response will get out of range - skip to the next range
        elif nextOid and oid == end:
            aclIdx += 1
            continue

        # OID in range
        elif begin <= oid <= end:
            # OID allowed, pass as-is
            return oid, aclIdx

        elif nextOid:
            aclIdx += 1

        else:
            break

    # non-matching OIDs
    return oid, None


def overrideLeakingOid(varBind, aclIdx,
                       mutedOids=None,
                       terminatedOids=None,
                       report=null):

    skip, begin, end = oidsList[aclIdx]

    oid, value = v2c.apiVarBind.getOIDVal(varBind)

    isAllowed = begin <= oid <= end

    aclIdx += 1

    if len(oidsList) == aclIdx:
        override = end

    else:
        skip, begin, end = oidsList[aclIdx]

        override = skip

    if not isAllowed:
        if value.isSameTypeWith(endOfMibView):
            report = endOfMibView

        if report is null:
            if mutedOids is not None:
                mutedOids.append((oid, override))
        else:
            if terminatedOids is not None:
                terminatedOids.append((oid, override))

        v2c.apiVarBind.setOIDVal(varBind, (override, report))

    return override

def processCommandRequest(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):

    reqOids = []

    reqCtx['req-oids'] = reqOids
    reqCtx['req-pdu'] = pdu

    if pdu.tagSet in (v2c.GetRequestPDU.tagSet, v2c.SetRequestPDU.tagSet):

        allDenied = True

        deniedOids = []

        for varBindIdx, varBind in enumerate(v2c.apiPDU.getVarBindList(pdu)):

            oid, val = v2c.apiVarBind.getOIDVal(varBind)

            oid = tuple(oid)

            skip, aclIdx = findAcl(oid)

            # skipped to the next OID
            if skip != oid:
                aclIdx = None

            # OID went out of range
            if aclIdx is None:
                # report OIDs we are sending errors for
                if logDenials:
                    deniedOids.append(str(varBind[0]))
            else:
                allDenied = False

            reqOids.append((oid, varBindIdx, aclIdx))

        if logDenials and deniedOids:
            denialMsg = formatDenialMsg(pdu, trunkMsg)
            denialMsg += ' OIDs ' + ', '.join(deniedOids)
            denialMsg += ' denied'
            error(denialMsg)

        reqVarBinds = v2c.VarBindList()

        if allDenied:
            pdu = v2c.apiPDU.getResponse(pdu)

            for oid, _, _ in reqOids:
                varBind = v2c.VarBind()
                v2c.apiVarBind.setOIDVal(varBind, (oid, noSuchInstance))
                reqVarBinds.append(varBind)

            nextAction = status.RESPOND

        else:
            for oid, _, aclIdx in reqOids:
                if aclIdx is None:
                    continue
                varBind = v2c.VarBind()
                v2c.apiVarBind.setOIDVal(varBind, (oid, null))
                reqVarBinds.append(varBind)

            nextAction = status.NEXT

        v2c.apiPDU.setVarBindList(pdu, reqVarBinds)

        return nextAction, pdu

    elif pdu.tagSet == v2c.GetNextRequestPDU.tagSet:

        allDenied = True

        skippedOids = []

        for varBindIdx, varBind in enumerate(v2c.apiPDU.getVarBindList(pdu)):

            oid, val = v2c.apiVarBind.getOIDVal(varBind)

            oid = tuple(oid)

            skip, aclIdx = findAcl(oid, nextOid=True)

            if logDenials and oid != skip:
                skippedOids.append((oid, skip))

            oid = skip

            # OID went out of range
            if aclIdx is not None:
                allDenied = False

            reqOids.append((oid, varBindIdx, aclIdx))

        if logDenials and skippedOids:
            denialMsg = formatDenialMsg(pdu, trunkMsg)
            denialMsg += ' ' + ', '.join(['%s not in range skipping to %s' % (v2c.ObjectIdentifier(x[0]), v2c.ObjectIdentifier(x[1])) for x in skippedOids])
            info(denialMsg)

        reqVarBinds = v2c.VarBindList()

        if allDenied:
            pdu = v2c.apiPDU.getResponse(pdu)

            for oid, _, _ in reqOids:
                varBind = v2c.VarBind()
                v2c.apiVarBind.setOIDVal(varBind, (oid, endOfMibView))
                reqVarBinds.append(varBind)

            nextAction = status.RESPOND

        else:
            for oid, _, aclIdx in reqOids:
                if aclIdx is None:
                    continue
                varBind = v2c.VarBind()
                v2c.apiVarBind.setOIDVal(varBind, (oid, null))
                reqVarBinds.append(varBind)

            nextAction = status.NEXT

        v2c.apiPDU.setVarBindList(pdu, reqVarBinds)

        return nextAction, pdu

    elif pdu.tagSet == v2c.GetBulkRequestPDU.tagSet:

        nonRepeaters = v2c.apiBulkPDU.getNonRepeaters(pdu)
        maxRepeaters = v2c.apiBulkPDU.getMaxRepetitions(pdu)

        nonRepOids = []
        linearizedOids = []
        repOids = []

        linearizedOidsMap = {}
        repeatersOidMap = {}

        reqCtx['linearized-oids-map'] = linearizedOidsMap
        reqCtx['repeaters-oids-map'] = repeatersOidMap

        reqCtx['non-repeaters'] = nonRepeaters

        allDenied = True

        skippedOids = []

        for varBindIdx, varBind in enumerate(v2c.apiBulkPDU.getVarBindList(pdu)):

            oid, val = v2c.apiVarBind.getOIDVal(varBind)

            oid = tuple(oid)

            skip, aclIdx = findAcl(oid, nextOid=True)

            if logDenials and oid != skip:
                skippedOids.append((oid, skip))

            oid = skip

            # original request var-binds
            reqOids.append((oid, varBindIdx, aclIdx))

            # OID went beyond all ranges
            if aclIdx is None:
                continue

            allDenied = False

            # original request non-repeaters
            if varBindIdx < nonRepeaters:
                nonRepOids.append((oid, varBindIdx, aclIdx))
                continue

            # original request repeaters
            skip, begin, end = oidsList[aclIdx]

            # move single-OID ranges from repeaters into non-repeaters
            startIdx = len(nonRepOids) + len(linearizedOids)
            endIdx = startIdx

            if begin == end:
                while endIdx - startIdx < maxRepeaters:
                    linearizedOids.append((oid, varBindIdx, aclIdx))
                    endIdx += 1
                    aclIdx += 1
                    if aclIdx >= len(endOids):
                        break
                    oid, begin, end = oidsList[aclIdx]
                    if begin != end:
                        break

                linearizedOidsMap[varBindIdx] = startIdx, endIdx

                debug('%s: repeating OID #%d (%s) converted into non-repeaters #%d..%d' % (PLUGIN_NAME, varBindIdx, varBind[0], startIdx, endIdx - 1))

                continue

            # proceed with original repeaters
            repeatersOidMap[varBindIdx] = len(repOids)

            repOids.append((oid, varBindIdx, aclIdx))

        if logDenials and skippedOids:
            denialMsg = formatDenialMsg(pdu, trunkMsg)
            denialMsg += ' ' + ', '.join(['%s not in range skipping to %s' % (v2c.ObjectIdentifier(x[0]), v2c.ObjectIdentifier(x[1])) for x in skippedOids])
            info(denialMsg)

        # assemble new var-binds
        reqVarBinds = v2c.VarBindList()

        if allDenied:
            pdu = v2c.apiBulkPDU.getResponse(pdu)

            for oid, _, _ in reqOids:
                varBind = v2c.VarBind()
                v2c.apiVarBind.setOIDVal(varBind, (oid, endOfMibView))
                reqVarBinds.append(varBind)

            nextAction = status.RESPOND

        else:

            for varBindIdx in repeatersOidMap:
                repeatersOidMap[varBindIdx] += len(nonRepOids) + len(linearizedOids)

            for oid, varBindIdx, aclIdx in nonRepOids + linearizedOids + repOids:
                if aclIdx is None:
                    continue

                varBind = v2c.VarBind()
                v2c.apiVarBind.setOIDVal(varBind, (oid, null))
                reqVarBinds.append(varBind)

            v2c.apiBulkPDU.setNonRepeaters(pdu, nonRepeaters + len(linearizedOids))

            nextAction = status.NEXT

        v2c.apiPDU.setVarBindList(pdu, reqVarBinds)

        return nextAction, pdu

    else:
        return status.NEXT, pdu


def processCommandResponse(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):
    if pdu.tagSet != v2c.GetResponsePDU.tagSet:
        return status.NEXT, pdu

    try:
        reqPdu = reqCtx['req-pdu']
        reqOids = reqCtx['req-oids']

    except KeyError:
        return status.NEXT, pdu

    if reqPdu.tagSet in (v2c.GetRequestPDU.tagSet,
                         v2c.SetRequestPDU.tagSet,
                         v2c.GetNextRequestPDU.tagSet):

        nextCmd = reqPdu.tagSet == v2c.GetNextRequestPDU.tagSet

        rspVarBinds = v2c.apiPDU.getVarBindList(pdu)

        terminatedOids = []
        mutedOids = []

        rspVarBindIdx = 0

        varBinds = v2c.VarBindList()

        for oid, reqVarBindIdx, aclIdx in reqOids:

            if aclIdx is None:
                varBind = v2c.VarBind()

                if nextCmd:
                    v2c.apiVarBind.setOIDVal(varBind, (oid, endOfMibView))
                else:
                    v2c.apiVarBind.setOIDVal(varBind, (oid, noSuchInstance))

            else:
                try:
                    varBind = rspVarBinds[rspVarBindIdx]

                except IndexError:
                    error('%s: missing response OID #%s' % (PLUGIN_NAME, rspVarBindIdx))
                    return status.DROP, pdu

                rspVarBindIdx += 1

                overrideLeakingOid(varBind, aclIdx, mutedOids, terminatedOids)

            varBinds.append(varBind)

        if logDenials and (terminatedOids or mutedOids):
            denialMsg = formatDenialMsg(pdu, trunkMsg)
            if terminatedOids:
                denialMsg += ' ' + 'OID(s) %s replaced with %s and reported as <end-of-mib>' % (','.join([str(v2c.ObjectIdentifier(x[0])) for x in terminatedOids]), ','.join([str(v2c.ObjectIdentifier(x[1])) for x in terminatedOids]))
            if mutedOids:
                denialMsg += ' ' + 'OID(s) %s replaced with %s and reported as <nil>' % (','.join([str(v2c.ObjectIdentifier(x[0])) for x in mutedOids]), ','.join([str(v2c.ObjectIdentifier(x[1])) for x in mutedOids]))
            info(denialMsg)

        v2c.apiPDU.setVarBindList(pdu, varBinds)

        return status.NEXT, pdu

    elif reqPdu.tagSet == v2c.GetBulkRequestPDU.tagSet:

        linearizedOidsMap = reqCtx['linearized-oids-map']
        if linearizedOidsMap:
            linearizedColumnDepth = max([x[1] - x[0] for x in linearizedOidsMap.values()])
        else:
            linearizedColumnDepth = 0

        repeatersOidsMap = reqCtx['repeaters-oids-map']

        origNonRepeaters = int(reqCtx['non-repeaters'])
        nonRepeaters = int(v2c.apiBulkPDU.getNonRepeaters(reqPdu))

        reqVarBinds = v2c.apiBulkPDU.getVarBindList(reqPdu)
        rspVarBinds = v2c.apiBulkPDU.getVarBindList(pdu)

        maxColumns = len(reqVarBinds) - nonRepeaters

        if maxColumns:
            columnDepth = (len(rspVarBinds) - nonRepeaters) // maxColumns

        else:
            columnDepth = 0

        if columnDepth < 0:
            error('%s: malformed GETBULK response table' % PLUGIN_NAME)
            return status.DROP, pdu

        maxColumnDepth = max(columnDepth, linearizedColumnDepth)

        nonRepVarBinds = []
        repVarBindTable = []

        terminatedOids = []
        mutedOids = []

        try:

            # Walk over original request var-binds
            for oid, reqVarBindIdx, aclIdx in reqOids:

                # copy over original non-repeaters
                if reqVarBindIdx < origNonRepeaters:
                    # locally terminated var-binds
                    if aclIdx is None:
                        varBind = v2c.VarBind()
                        v2c.apiVarBind.setOIDVal(varBind, (oid, endOfMibView))

                    else:
                        varBind = rspVarBinds[reqVarBindIdx]

                        overrideLeakingOid(varBind, aclIdx, mutedOids, terminatedOids)

                    nonRepVarBinds.append(varBind)

                    continue

                # process linearized OIDs
                elif reqVarBindIdx in linearizedOidsMap:
                    startIdx, endIdx = linearizedOidsMap[reqVarBindIdx]

                    override = oid

                    repVarBindTable.append([])

                    # move non-repeaters into repeaters as individual columns
                    for rspVarBindIdx in range(startIdx, endIdx):

                        if rspVarBindIdx - startIdx < maxColumnDepth:
                            varBind = rspVarBinds[rspVarBindIdx]

                            override = overrideLeakingOid(varBind, aclIdx, mutedOids, terminatedOids)

                            repVarBindTable[-1].append(varBind)

                            # this assumes that aclIdx grows with endIdx
                            aclIdx += 1

                        else:
                            break

                    # pad insufficient rows
                    insufficientRows = maxColumnDepth - (endIdx - startIdx)

                    while insufficientRows:
                        varBind = v2c.VarBind()
                        v2c.apiVarBind.setOIDVal(varBind, (override, null))
                        repVarBindTable[-1].append(varBind)
                        insufficientRows -= 1

                # copy over original repeaters into individual columns
                elif reqVarBindIdx in repeatersOidsMap:
                    override = oid

                    repVarBindTable.append([])

                    startIdx = repeatersOidsMap[reqVarBindIdx]

                    for row in range(maxColumnDepth):

                        if aclIdx is not None and row < columnDepth:
                            rspVarBindIdx = startIdx + maxColumns * row

                            varBind = rspVarBinds[rspVarBindIdx]

                            override = overrideLeakingOid(varBind, aclIdx, mutedOids, terminatedOids)

                        else:
                            varBind = v2c.VarBind()
                            v2c.apiVarBind.setOIDVal(varBind, (override, null))

                        repVarBindTable[-1].append(varBind)

                else:
                    error('%s: malformed GETBULK state information!' % PLUGIN_NAME)
                    return status.DROP, pdu

        except IndexError:
            error('%s: short GETBULK response PDU' % PLUGIN_NAME)
            return status.DROP, pdu

        if logDenials and (terminatedOids or mutedOids):
            denialMsg = formatDenialMsg(pdu, trunkMsg)
            if terminatedOids:
                denialMsg += ' ' + 'OID(s) %s replaced with %s and reported as <end-of-mib>' % (','.join([str(v2c.ObjectIdentifier(x[0])) for x in terminatedOids]), ','.join([str(v2c.ObjectIdentifier(x[1])) for x in terminatedOids]))
            if mutedOids:
                denialMsg += ' ' + 'OID(s) %s replaced with %s and reported as <nil>' % (','.join([str(v2c.ObjectIdentifier(x[0])) for x in mutedOids]), ','.join([str(v2c.ObjectIdentifier(x[1])) for x in mutedOids]))
            info(denialMsg)

        varBinds = v2c.VarBindList()

        for varBind in nonRepVarBinds:
            varBinds.append(varBind)

        for row in range(maxColumnDepth):
            for repVarBinds in repVarBindTable:
                varBinds.append(repVarBinds[row])

        v2c.apiBulkPDU.setVarBindList(pdu, varBinds)

        return status.NEXT, pdu

    else:
        return status.NEXT, pdu


def processNotificationRequest(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):
    if pdu.tagSet not in (v2c.SNMPv2TrapPDU.tagSet, v2c.InformRequestPDU.tagSet):
        return status.NEXT, pdu

    deniedOids = []

    varBinds = v2c.VarBindList()

    for varBind in v2c.apiTrapPDU.getVarBindList(pdu):

        oid, val = v2c.apiVarBind.getOIDVal(varBind)

        oid = tuple(oid)

        skip, aclIdx = findAcl(oid)

        # skipped to the next OID
        if skip != oid:
            aclIdx = None

        # OID went out of range
        if aclIdx is None:
            if logDenials:
                deniedOids.append(str(varBind[0]))
            continue

        varBinds.append(varBind)

    if logDenials and deniedOids:
        denialMsg = formatDenialMsg(pdu, trunkMsg)
        denialMsg += ' OIDs ' + ', '.join(deniedOids)
        denialMsg += ' denied'
        error(denialMsg)

    if not varBinds:
        return status.DROP, pdu

    v2c.apiPDU.setVarBindList(pdu, varBinds)

    return status.NEXT, pdu
