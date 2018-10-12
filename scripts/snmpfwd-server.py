#!/usr/bin/env python
#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import os
import sys
import getopt
import traceback
import random
import re
import socket
from pysnmp.error import PySnmpError
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, ntfrcv, context
from pysnmp.proto.proxy import rfc2576
from pysnmp.carrier.asynsock.dgram import udp
try:
    from pysnmp.carrier.asynsock.dgram import udp6
except ImportError:
    udp6 = None
try:
    from pysnmp.carrier.asynsock.dgram import unix
except ImportError:
    unix = None
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.proto import rfc1157, rfc1902, rfc1905
from pysnmp.proto.api import v1, v2c
from pyasn1 import debug as pyasn1_debug
from pysnmp import debug as pysnmp_debug
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, daemon, cparser, macro, endpoint
from snmpfwd.plugins.manager import PluginManager
from snmpfwd.plugins import status
from snmpfwd.trunking.manager import TrunkingManager
from snmpfwd.trunking.endpoint import parseTrunkEndpoint
from snmpfwd.lazylog import LazyLogString

# Settings
PROGRAM_NAME = 'snmpfwd-server'
CONFIG_VERSION = '2'
PLUGIN_API_VERSION = 2
CONFIG_FILE = '/usr/local/etc/snmpfwd/server.cfg'

authProtocols = {
  'MD5': config.usmHMACMD5AuthProtocol,
  'SHA': config.usmHMACSHAAuthProtocol,
  'SHA224': config.usmHMAC128SHA224AuthProtocol,
  'SHA256': config.usmHMAC192SHA256AuthProtocol,
  'SHA384': config.usmHMAC256SHA384AuthProtocol,
  'SHA512': config.usmHMAC384SHA512AuthProtocol,
  'NONE': config.usmNoAuthProtocol
}

privProtocols = {
  'DES': config.usmDESPrivProtocol,
  '3DES': config.usm3DESEDEPrivProtocol,
  'AES': config.usmAesCfb128Protocol,
  'AES128': config.usmAesCfb128Protocol,
  'AES192': config.usmAesCfb192Protocol,
  'AES192BLMT': config.usmAesBlumenthalCfb192Protocol,
  'AES256': config.usmAesCfb256Protocol,
  'AES256BLMT': config.usmAesBlumenthalCfb256Protocol,
  'NONE': config.usmNoPrivProtocol
}

snmpPduTypesMap = {
    rfc1905.GetRequestPDU.tagSet: 'GET',
    rfc1905.SetRequestPDU.tagSet: 'SET',
    rfc1905.GetNextRequestPDU.tagSet: 'GETNEXT',
    rfc1905.GetBulkRequestPDU.tagSet: 'GETBULK',
    rfc1905.ResponsePDU.tagSet: 'RESPONSE',
    rfc1157.TrapPDU.tagSet: 'TRAPv1',
    rfc1905.SNMPv2TrapPDU.tagSet: 'TRAPv2'
}


def main():

    class CommandResponder(cmdrsp.CommandResponderBase):
        pduTypes = (rfc1905.SetRequestPDU.tagSet,
                    rfc1905.GetRequestPDU.tagSet,
                    rfc1905.GetNextRequestPDU.tagSet,
                    rfc1905.GetBulkRequestPDU.tagSet)

        def handleMgmtOperation(self, snmpEngine, stateReference, contextName,
                                pdu, acInfo):
            trunkReq = gCurrentRequestContext.copy()

            trunkReq['snmp-pdu'] = pdu

            pluginIdList = trunkReq['plugins-list']

            logCtx = LogString(trunkReq)

            reqCtx = {}

            for pluginNum, pluginId in enumerate(pluginIdList):

                st, pdu = pluginManager.processCommandRequest(
                    pluginId, snmpEngine, pdu, trunkReq, reqCtx
                )

                if st == status.BREAK:
                    log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                    pluginIdList = pluginIdList[:pluginNum]
                    break

                elif st == status.DROP:
                    log.debug('received SNMP message, plugin %s muted request' % pluginId, ctx=logCtx)
                    self.releaseStateInformation(stateReference)
                    return

                elif st == status.RESPOND:
                    log.debug('received SNMP message, plugin %s forced immediate response' % pluginId, ctx=logCtx)

                    try:
                        self.sendPdu(snmpEngine, stateReference, pdu)

                    except PySnmpError:
                        log.error('failure sending SNMP response', ctx=logCtx)

                    else:
                        self.releaseStateInformation(stateReference)

                    return

            # pass query to trunk

            trunkIdList = trunkReq['trunk-id-list']
            if trunkIdList is None:
                log.error('no route configured', ctx=logCtx)
                self.releaseStateInformation(stateReference)
                return

            for trunkId in trunkIdList:

                cbCtx = pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx

                try:
                    msgId = trunkingManager.sendReq(trunkId, trunkReq, self.trunkCbFun, cbCtx)

                except SnmpfwdError:
                    log.error('received SNMP message, message not sent to trunk "%s"' % sys.exc_info()[1], ctx=logCtx)
                    return

                log.debug('received SNMP message, forwarded as trunk message #%s' % msgId, ctx=logCtx)

        def trunkCbFun(self, msgId, trunkRsp, cbCtx):
            pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx = cbCtx

            for key in tuple(trunkRsp):
                if key != 'callflow-id':
                    trunkRsp['client-' + key] = trunkRsp[key]
                    del trunkRsp[key]

            trunkRsp['callflow-id'] = trunkReq['callflow-id']

            logCtx = LogString(trunkRsp)

            if trunkRsp['client-error-indication']:
                log.info('received trunk message #%s, remote end reported error-indication "%s", NOT responding' % (msgId, trunkRsp['client-error-indication']), ctx=logCtx)

            elif 'client-snmp-pdu' not in trunkRsp:
                log.info('received trunk message #%s, remote end does not send SNMP PDU, NOT responding' % msgId, ctx=logCtx)

            else:
                pdu = trunkRsp['client-snmp-pdu']

                for pluginId in pluginIdList:
                    st, pdu = pluginManager.processCommandResponse(
                        pluginId, snmpEngine, pdu, trunkReq, reqCtx
                    )

                    if st == status.BREAK:
                        log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                        break
                    elif st == status.DROP:
                        log.debug('plugin %s muted response' % pluginId, ctx=logCtx)
                        self.releaseStateInformation(stateReference)
                        return

                try:
                    self.sendPdu(snmpEngine, stateReference, pdu)

                except PySnmpError:
                    log.error('failure sending SNMP response', ctx=logCtx)

                else:
                    log.debug('received trunk message #%s, forwarded as SNMP message' % msgId, ctx=logCtx)

            self.releaseStateInformation(stateReference)

    #
    # SNMPv3 NotificationReceiver implementation
    #

    class NotificationReceiver(ntfrcv.NotificationReceiver):
        pduTypes = (rfc1157.TrapPDU.tagSet,
                    rfc1905.SNMPv2TrapPDU.tagSet)

        def processPdu(self, snmpEngine, messageProcessingModel,
                       securityModel, securityName, securityLevel,
                       contextEngineId, contextName, pduVersion, pdu,
                       maxSizeResponseScopedPDU, stateReference):

            trunkReq = gCurrentRequestContext.copy()

            if messageProcessingModel == 0:
                pdu = rfc2576.v1ToV2(pdu)

            trunkReq['snmp-pdu'] = pdu

            pluginIdList = trunkReq['plugins-list']

            logCtx = LogString(trunkReq)

            reqCtx = {}

            for pluginNum, pluginId in enumerate(pluginIdList):

                st, pdu = pluginManager.processNotificationRequest(
                    pluginId, snmpEngine, pdu, trunkReq, reqCtx
                )

                if st == status.BREAK:
                    log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                    pluginIdList = pluginIdList[:pluginNum]
                    break

                elif st == status.DROP:
                    log.debug('plugin %s muted request' % pluginId, ctx=logCtx)
                    return

                elif st == status.RESPOND:
                    log.debug('plugin %s NOT forced immediate response' % pluginId, ctx=logCtx)
                    # TODO: implement immediate response for confirmed-class PDU
                    return

            # pass query to trunk

            trunkIdList = trunkReq['trunk-id-list']
            if trunkIdList is None:
                log.error('no route configured', ctx=logCtx)
                return

            for trunkId in trunkIdList:

                # TODO: pass messageProcessingModel to respond
                cbCtx = pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx

                try:
                    msgId = trunkingManager.sendReq(trunkId, trunkReq, self.trunkCbFun, cbCtx)

                except SnmpfwdError:
                    log.error('received SNMP message, message not sent to trunk "%s" %s' % (trunkId, sys.exc_info()[1]), ctx=logCtx)
                    return

                log.debug('received SNMP message, forwarded as trunk message #%s' % msgId, ctx=logCtx)

        def trunkCbFun(self, msgId, trunkRsp, cbCtx):
            pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx = cbCtx

            for key in tuple(trunkRsp):
                if key != 'callflow-id':
                    trunkRsp['client-' + key] = trunkRsp[key]
                    del trunkRsp[key]

            trunkRsp['callflow-id'] = trunkReq['callflow-id']

            logCtx = LazyLogString(trunkReq, trunkRsp)

            if trunkRsp['client-error-indication']:
                log.info('received trunk message #%s, remote end reported error-indication "%s", NOT responding' % (msgId, trunkRsp['client-error-indication']), ctx=logCtx)
            else:
                if 'client-snmp-pdu' not in trunkRsp:
                    log.debug('received trunk message #%s -- unconfirmed SNMP message' % msgId, ctx=logCtx)
                    return

                pdu = trunkRsp['client-snmp-pdu']

                for pluginId in pluginIdList:
                    st, pdu = pluginManager.processNotificationResponse(
                        pluginId, snmpEngine, pdu, trunkReq, reqCtx
                    )

                    if st == status.BREAK:
                        log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                        break
                    elif st == status.DROP:
                        log.debug('received trunk message #%s, plugin %s muted response' % (msgId, pluginId), ctx=logCtx)
                        return

                log.debug('received trunk message #%s, forwarded as SNMP message' % msgId, ctx=logCtx)

                # TODO: implement response part

                # # Agent-side API complies with SMIv2
                # if messageProcessingModel == 0:
                #     PDU = rfc2576.v2ToV1(PDU, origPdu)
                #
                # statusInformation = {}
                #
                # # 3.4.3
                # try:
                #     snmpEngine.msgAndPduDsp.returnResponsePdu(
                #         snmpEngine, messageProcessingModel, securityModel,
                #         securityName, securityLevel, contextEngineId,
                #         contextName, pduVersion, rspPDU, maxSizeResponseScopedPDU,
                #         stateReference, statusInformation)
                #
                # except error.StatusInformation:
                #         log.error('processPdu: stateReference %s, statusInformation %s' % (stateReference, sys.exc_info()[1]))

    class LogString(LazyLogString):

        GROUPINGS = [
            ['callflow-id'],
            ['snmp-engine-id',
             'snmp-transport-domain',
             'snmp-bind-address',
             'snmp-bind-port',
             'snmp-security-model',
             'snmp-security-level',
             'snmp-security-name',
             'snmp-credentials-id'],
            ['snmp-context-engine-id',
             'snmp-context-name',
             'snmp-context-id'],
            ['snmp-pdu',
             'snmp-content-id'],
            ['snmp-peer-address',
             'snmp-peer-port',
             'snmp-peer-id'],
            ['trunk-id'],
            ['client-snmp-pdu'],
        ]

        FORMATTERS = {
            'client-snmp-pdu': LazyLogString.prettyVarBinds,
            'snmp-pdu': LazyLogString.prettyVarBinds,
        }

    def securityAuditObserver(snmpEngine, execpoint, variables, cbCtx):
        securityModel = variables.get('securityModel', 0)

        logMsg = 'SNMPv%s auth failure' % securityModel
        logMsg += ' at %s:%s' % variables['transportAddress'].getLocalAddress()
        logMsg += ' from %s:%s' % variables['transportAddress']

        statusInformation = variables.get('statusInformation', {})

        if securityModel in (1, 2):
            logMsg += ' using snmp-community-name "%s"' % statusInformation.get('communityName', '?')
        elif securityModel == 3:
            logMsg += ' using snmp-usm-user "%s"' % statusInformation.get('msgUserName', '?')

        try:
            logMsg += ': %s' % statusInformation['errorIndication']

        except KeyError:
            pass

        log.error(logMsg)

    def usmRequestObserver(snmpEngine, execpoint, variables, cbCtx):

        trunkReq = {
            'snmp-security-engine-id': variables['securityEngineId']
        }

        cbCtx.clear()
        cbCtx.update(trunkReq)

    def requestObserver(snmpEngine, execpoint, variables, cbCtx):

        trunkReq = {
            'callflow-id': '%10.10x' % random.randint(0, 0xffffffffff),
            'snmp-engine-id': snmpEngine.snmpEngineID,
            'snmp-transport-domain': variables['transportDomain'],
            'snmp-peer-address': variables['transportAddress'][0],
            'snmp-peer-port': variables['transportAddress'][1],
            'snmp-bind-address': variables['transportAddress'].getLocalAddress()[0],
            'snmp-bind-port': variables['transportAddress'].getLocalAddress()[1],
            'snmp-security-model': variables['securityModel'],
            'snmp-security-level': variables['securityLevel'],
            'snmp-security-name': variables['securityName'],
            'snmp-context-engine-id': variables['contextEngineId'],
            'snmp-context-name': variables['contextName'],
        }

        try:
            trunkReq['snmp-security-engine-id'] = cbCtx.pop('snmp-security-engine-id')

        except KeyError:
            # SNMPv1/v2c
            trunkReq['snmp-security-engine-id'] = trunkReq['snmp-engine-id']

        trunkReq['snmp-credentials-id'] = macro.expandMacro(
            credIdMap.get(
                (str(snmpEngine.snmpEngineID),
                 variables['transportDomain'],
                 variables['securityModel'],
                 variables['securityLevel'],
                 str(variables['securityName']))
            ),
            trunkReq
        )

        k = '#'.join([str(x) for x in (variables['contextEngineId'], variables['contextName'])])
        for x, y in contextIdList:
            if y.match(k):
                trunkReq['snmp-context-id'] = macro.expandMacro(x, trunkReq)
                break
            else:
                trunkReq['snmp-context-id'] = None

        addr = '%s:%s#%s:%s' % (variables['transportAddress'][0], variables['transportAddress'][1], variables['transportAddress'].getLocalAddress()[0], variables['transportAddress'].getLocalAddress()[1])

        for pat, peerId in peerIdMap.get(str(variables['transportDomain']), ()):
            if pat.match(addr):
                trunkReq['snmp-peer-id'] = macro.expandMacro(peerId, trunkReq)
                break
        else:
            trunkReq['snmp-peer-id'] = None

        pdu = variables['pdu']
        if pdu.tagSet == v1.TrapPDU.tagSet:
            pdu = rfc2576.v1ToV2(pdu)
            v2c.apiTrapPDU.setDefaults(pdu)

        k = '#'.join(
            [snmpPduTypesMap.get(variables['pdu'].tagSet, '?'),
             '|'.join([str(x[0]) for x in v2c.apiTrapPDU.getVarBinds(pdu)])]
        )

        for x, y in contentIdList:
            if y.match(k):
                trunkReq['snmp-content-id'] = macro.expandMacro(x, trunkReq)
                break
            else:
                trunkReq['snmp-content-id'] = None

        trunkReq['plugins-list'] = pluginIdMap.get(
            (trunkReq['snmp-credentials-id'],
             trunkReq['snmp-context-id'],
             trunkReq['snmp-peer-id'],
             trunkReq['snmp-content-id']), []
        )
        trunkReq['trunk-id-list'] = trunkIdMap.get(
            (trunkReq['snmp-credentials-id'],
             trunkReq['snmp-context-id'],
             trunkReq['snmp-peer-id'],
             trunkReq['snmp-content-id'])
        )

        cbCtx.clear()
        cbCtx.update(trunkReq)

    #
    # main script starts here
    #

    helpMessage = """\
Usage: %s [--help]
    [--version ]
    [--debug-snmp=<%s>]
    [--debug-asn1=<%s>]
    [--daemonize]
    [--process-user=<uname>] [--process-group=<gname>]
    [--pid-file=<file>]
    [--logging-method=<%s[:args>]>]
    [--log-level=<%s>]
    [--config-file=<file>]""" % (
        sys.argv[0],
        '|'.join([x for x in pysnmp_debug.flagMap.keys() if x != 'mibview']),
        '|'.join([x for x in pyasn1_debug.flagMap.keys()]),
        '|'.join(log.methodsMap.keys()),
        '|'.join(log.levelsMap)
    )

    try:
        opts, params = getopt.getopt(sys.argv[1:], 'hv', [
            'help', 'version', 'debug=', 'debug-snmp=', 'debug-asn1=', 'daemonize',
            'process-user=', 'process-group=', 'pid-file=', 'logging-method=',
            'log-level=', 'config-file='
        ])

    except Exception:
        sys.stderr.write('ERROR: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
        return

    if params:
        sys.stderr.write('ERROR: extra arguments supplied %s\r\n%s\r\n' % (params, helpMessage))
        return

    pidFile = ''
    cfgFile = CONFIG_FILE
    foregroundFlag = True
    procUser = procGroup = None

    loggingMethod = ['stderr']
    loggingLevel = None

    for opt in opts:
        if opt[0] == '-h' or opt[0] == '--help':
            sys.stderr.write("""\
Synopsis:
  SNMP Proxy Forwarder: server part. Receives SNMP requests at one or many
  built-in SNMP Agents and routes them to encrypted trunks established with
  Forwarder's Manager part(s) running elsewhere.
  Can implement complex routing logic through analyzing parts of SNMP messages
  and matching them against proxy rules.

Documentation:
  http://snmplabs.com/snmpfwd/

%s
""" % helpMessage)
            return
        if opt[0] == '-v' or opt[0] == '--version':
            import snmpfwd
            import pysnmp
            import pyasn1
            sys.stderr.write("""\
SNMP Proxy Forwarder version %s, written by Ilya Etingof <etingof@gmail.com>
Using foundation libraries: pysnmp %s, pyasn1 %s.
Python interpreter: %s
Software documentation and support at http://snmplabs.com/snmpfwd/
%s
""" % (snmpfwd.__version__, hasattr(pysnmp, '__version__') and pysnmp.__version__ or 'unknown',
               hasattr(pyasn1, '__version__') and pyasn1.__version__ or 'unknown', sys.version, helpMessage))
            return
        elif opt[0] == '--debug-snmp':
            pysnmp_debug.setLogger(pysnmp_debug.Debug(*opt[1].split(','), **dict(loggerName=PROGRAM_NAME + '.pysnmp')))
        elif opt[0] == '--debug-asn1':
            pyasn1_debug.setLogger(pyasn1_debug.Debug(*opt[1].split(','), **dict(loggerName=PROGRAM_NAME + '.pyasn1')))
        elif opt[0] == '--daemonize':
            foregroundFlag = False
        elif opt[0] == '--process-user':
            procUser = opt[1]
        elif opt[0] == '--process-group':
            procGroup = opt[1]
        elif opt[0] == '--pid-file':
            pidFile = opt[1]
        elif opt[0] == '--logging-method':
            loggingMethod = opt[1].split(':')
        elif opt[0] == '--log-level':
            loggingLevel = opt[1]
        elif opt[0] == '--config-file':
            cfgFile = opt[1]

    try:
        log.setLogger(PROGRAM_NAME, *loggingMethod, **dict(force=True))

        if loggingLevel:
            log.setLevel(loggingLevel)

    except SnmpfwdError:
        sys.stderr.write('%s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
        return

    try:
        cfgTree = cparser.Config().load(cfgFile)
    except SnmpfwdError:
        log.error('configuration parsing error: %s' % sys.exc_info()[1])
        return

    if cfgTree.getAttrValue('program-name', '', default=None) != PROGRAM_NAME:
        log.error('config file %s does not match program name %s' % (cfgFile, PROGRAM_NAME))
        return

    if cfgTree.getAttrValue('config-version', '', default=None) != CONFIG_VERSION:
        log.error('config file %s version is not compatible with program version %s' % (cfgFile, CONFIG_VERSION))
        return

    random.seed()

    gCurrentRequestContext = {}

    credIdMap = {}
    peerIdMap = {}
    contextIdList = []
    contentIdList = []
    pluginIdMap = {}
    trunkIdMap = {}
    engineIdMap = {}

    transportDispatcher = AsynsockDispatcher()
    transportDispatcher.registerRoutingCbFun(lambda td, t, d: td)
    transportDispatcher.setSocketMap()  # use global asyncore socket map

    #
    # Initialize plugin modules
    #

    pluginManager = PluginManager(
        macro.expandMacros(
            cfgTree.getAttrValue('plugin-modules-path-list', '', default=[], vector=True),
            {'config-dir': os.path.dirname(cfgFile)}
        ),
        progId=PROGRAM_NAME,
        apiVer=PLUGIN_API_VERSION
    )

    for pluginCfgPath in cfgTree.getPathsToAttr('plugin-id'):
        pluginId = cfgTree.getAttrValue('plugin-id', *pluginCfgPath)
        pluginMod = cfgTree.getAttrValue('plugin-module', *pluginCfgPath)
        pluginOptions = macro.expandMacros(
            cfgTree.getAttrValue('plugin-options', *pluginCfgPath, **dict(default=[], vector=True)),
            {'config-dir': os.path.dirname(cfgFile)}
        )

        log.info('configuring plugin ID %s (at %s) from module %s with options %s...' % (pluginId, '.'.join(pluginCfgPath), pluginMod, ', '.join(pluginOptions) or '<none>'))

        try:
            pluginManager.loadPlugin(pluginId, pluginMod, pluginOptions)

        except SnmpfwdError:
            log.error('plugin %s not loaded: %s' % (pluginId, sys.exc_info()[1]))
            return

    for configEntryPath in cfgTree.getPathsToAttr('snmp-credentials-id'):
        credId = cfgTree.getAttrValue('snmp-credentials-id', *configEntryPath)
        configKey = []
        log.info('configuring snmp-credentials %s (at %s)...' % (credId, '.'.join(configEntryPath)))

        engineId = cfgTree.getAttrValue('snmp-engine-id', *configEntryPath)

        if engineId in engineIdMap:
            snmpEngine, snmpContext, snmpEngineMap = engineIdMap[engineId]
            log.info('using engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())
        else:
            snmpEngine = engine.SnmpEngine(snmpEngineID=engineId)
            snmpContext = context.SnmpContext(snmpEngine)
            snmpEngineMap = {
                'transportDomain': {},
                'securityName': {}
            }

            snmpEngine.observer.registerObserver(
                securityAuditObserver,
                'rfc2576.prepareDataElements:sm-failure',
                'rfc3412.prepareDataElements:sm-failure',
                cbCtx=gCurrentRequestContext
            )

            snmpEngine.observer.registerObserver(
                requestObserver,
                'rfc3412.receiveMessage:request',
                cbCtx=gCurrentRequestContext
            )

            snmpEngine.observer.registerObserver(
                usmRequestObserver,
                'rfc3414.processIncomingMsg',
                cbCtx=gCurrentRequestContext
            )

            CommandResponder(snmpEngine, snmpContext)

            NotificationReceiver(snmpEngine, None)

            engineIdMap[engineId] = snmpEngine, snmpContext, snmpEngineMap

            log.info('new engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())

        configKey.append(str(snmpEngine.snmpEngineID))

        transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *configEntryPath)
        transportDomain = rfc1902.ObjectName(transportDomain)

        if (transportDomain[:len(udp.domainName)] != udp.domainName and
                udp6 and transportDomain[:len(udp6.domainName)] != udp6.domainName):
            log.error('unknown transport domain %s' % (transportDomain,))
            return

        if transportDomain in snmpEngineMap['transportDomain']:
            h, p, transportDomain = snmpEngineMap['transportDomain'][transportDomain]
            log.info('using transport endpoint [%s]:%s, transport ID %s' % (h, p, transportDomain))

        else:
            bindAddr = cfgTree.getAttrValue('snmp-bind-address', *configEntryPath)

            transportOptions = cfgTree.getAttrValue('snmp-transport-options', *configEntryPath, **dict(default=[], vector=True))

            try:
                bindAddr, bindAddrMacro = endpoint.parseTransportAddress(transportDomain, bindAddr,
                                                                         transportOptions)

            except SnmpfwdError:
                log.error('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(configEntryPath)))
                return

            if transportDomain[:len(udp.domainName)] == udp.domainName:
                transport = udp.UdpTransport()
            else:
                transport = udp6.Udp6Transport()

            t = transport.openServerMode(bindAddr)

            if 'transparent-proxy' in transportOptions:
                t.enablePktInfo()
                t.enableTransparent()
            elif 'virtual-interface' in transportOptions:
                t.enablePktInfo()

            snmpEngine.registerTransportDispatcher(
                transportDispatcher, transportDomain
            )

            config.addSocketTransport(snmpEngine, transportDomain, t)

            snmpEngineMap['transportDomain'][transportDomain] = bindAddr, transportDomain

            log.info('new transport endpoint [%s]:%s, options %s, transport ID %s' % (bindAddr[0], bindAddr[1], transportOptions and '/'.join(transportOptions) or '<none>', transportDomain))

        configKey.append(transportDomain)

        securityModel = cfgTree.getAttrValue('snmp-security-model', *configEntryPath)
        securityModel = rfc1902.Integer(securityModel)
        securityLevel = cfgTree.getAttrValue('snmp-security-level', *configEntryPath)
        securityLevel = rfc1902.Integer(securityLevel)
        securityName = cfgTree.getAttrValue('snmp-security-name', *configEntryPath)

        if securityModel in (1, 2):
            if securityName in snmpEngineMap['securityName']:
                if snmpEngineMap['securityName'][securityModel] == securityModel:
                    log.info('using security-name %s' % securityName)
                else:
                    raise SnmpfwdError('snmp-security-name %s already in use at snmp-security-model %s' % (securityName, securityModel))
            else:
                communityName = cfgTree.getAttrValue('snmp-community-name', *configEntryPath)
                config.addV1System(snmpEngine, securityName, communityName,
                                   securityName=securityName)
                log.info('new community-name %s, security-model %s, security-name %s, security-level %s' % (communityName, securityModel, securityName, securityLevel))
                snmpEngineMap['securityName'][securityName] = securityModel

            configKey.append(securityModel)
            configKey.append(securityLevel)
            configKey.append(securityName)

        elif securityModel == 3:
            if securityName in snmpEngineMap['securityName']:
                log.info('using USM security-name: %s' % securityName)
            else:
                usmUser = cfgTree.getAttrValue('snmp-usm-user', *configEntryPath)
                securityEngineId = cfgTree.getAttrValue('snmp-security-engine-id', *configEntryPath,
                                                        **dict(default=None))
                if securityEngineId:
                    securityEngineId = rfc1902.OctetString(securityEngineId)

                log.info('new USM user %s, security-model %s, security-level %s, '
                         'security-name %s, security-engine-id %s' % (usmUser, securityModel, securityLevel,
                                                                      securityName, securityEngineId and securityEngineId.prettyPrint() or '<none>'))

                if securityLevel in (2, 3):
                    usmAuthProto = cfgTree.getAttrValue('snmp-usm-auth-protocol', *configEntryPath, **dict(default=config.usmHMACMD5AuthProtocol))
                    try:
                        usmAuthProto = authProtocols[usmAuthProto.upper()]
                    except KeyError:
                        pass
                    usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                    usmAuthKey = cfgTree.getAttrValue('snmp-usm-auth-key', *configEntryPath)
                    log.info('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                    if securityLevel == 3:
                        usmPrivProto = cfgTree.getAttrValue('snmp-usm-priv-protocol', *configEntryPath, **dict(default=config.usmDESPrivProtocol))
                        try:
                            usmPrivProto = privProtocols[usmPrivProto.upper()]
                        except KeyError:
                            pass
                        usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                        usmPrivKey = cfgTree.getAttrValue('snmp-usm-priv-key', *configEntryPath, **dict(default=None))
                        log.info('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))

                        config.addV3User(
                            snmpEngine, usmUser,
                            usmAuthProto, usmAuthKey,
                            usmPrivProto, usmPrivKey,
                            securityEngineId=securityEngineId
                        )

                    else:
                        config.addV3User(snmpEngine, usmUser,
                                         usmAuthProto, usmAuthKey,
                                         securityEngineId=securityEngineId)

                else:
                    config.addV3User(snmpEngine, usmUser,
                                     securityEngineId=securityEngineId)

                snmpEngineMap['securityName'][securityName] = securityModel

            configKey.append(securityModel)
            configKey.append(securityLevel)
            configKey.append(securityName)

        else:
            raise SnmpfwdError('unknown snmp-security-model: %s' % securityModel)

        configKey = tuple(configKey)
        if configKey in credIdMap:
            log.error('ambiguous configuration for key snmp-credentials-id=%s at %s' % (credId, '.'.join(configEntryPath)))
            return

        credIdMap[configKey] = credId

    duplicates = {}

    for peerCfgPath in cfgTree.getPathsToAttr('snmp-peer-id'):
        peerId = cfgTree.getAttrValue('snmp-peer-id', *peerCfgPath)
        if peerId in duplicates:
            log.error('duplicate snmp-peer-id=%s at %s and %s' % (peerId, '.'.join(peerCfgPath), '.'.join(duplicates[peerId])))
            return

        duplicates[peerId] = peerCfgPath

        log.info('configuring peer ID %s (at %s)...' % (peerId, '.'.join(peerCfgPath)))
        transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *peerCfgPath)
        if transportDomain not in peerIdMap:
            peerIdMap[transportDomain] = []
        for peerAddress in cfgTree.getAttrValue('snmp-peer-address-pattern-list', *peerCfgPath, **dict(vector=True)):
            for bindAddress in cfgTree.getAttrValue('snmp-bind-address-pattern-list', *peerCfgPath, **dict(vector=True)):
                peerIdMap[transportDomain].append(
                    (re.compile(peerAddress+'#'+bindAddress), peerId)
                )

    duplicates = {}

    for contextCfgPath in cfgTree.getPathsToAttr('snmp-context-id'):
        contextId = cfgTree.getAttrValue('snmp-context-id', *contextCfgPath)
        if contextId in duplicates:
            log.error('duplicate snmp-context-id=%s at %s and %s' % (contextId, '.'.join(contextCfgPath), '.'.join(duplicates[contextId])))
            return

        duplicates[contextId] = contextCfgPath

        k = '#'.join(
            (cfgTree.getAttrValue('snmp-context-engine-id-pattern', *contextCfgPath),
             cfgTree.getAttrValue('snmp-context-name-pattern', *contextCfgPath))
        )

        log.info('configuring context ID %s (at %s), composite key: %s' % (contextId, '.'.join(contextCfgPath), k))

        contextIdList.append((contextId, re.compile(k)))

    duplicates = {}

    for contentCfgPath in cfgTree.getPathsToAttr('snmp-content-id'):
        contentId = cfgTree.getAttrValue('snmp-content-id', *contentCfgPath)
        if contentId in duplicates:
            log.error('duplicate snmp-content-id=%s at %s and %s' % (contentId, '.'.join(contentCfgPath), '.'.join(duplicates[contentId])))
            return

        duplicates[contentId] = contentCfgPath

        for x in cfgTree.getAttrValue('snmp-pdu-oid-prefix-pattern-list', *contentCfgPath, **dict(vector=True)):
            k = '#'.join([cfgTree.getAttrValue('snmp-pdu-type-pattern', *contentCfgPath), x])

            log.info('configuring content ID %s (at %s), composite key: %s' % (contentId, '.'.join(contentCfgPath), k))

            contentIdList.append((contentId, re.compile(k)))

    del duplicates

    for pluginCfgPath in cfgTree.getPathsToAttr('using-plugin-id-list'):
        pluginIdList = cfgTree.getAttrValue('using-plugin-id-list', *pluginCfgPath, **dict(vector=True))
        log.info('configuring plugin ID(s) %s (at %s)...' % (','.join(pluginIdList), '.'.join(pluginCfgPath)))
        for credId in cfgTree.getAttrValue('matching-snmp-credentials-id-list', *pluginCfgPath, **dict(vector=True)):
            for peerId in cfgTree.getAttrValue('matching-snmp-peer-id-list', *pluginCfgPath, **dict(vector=True)):
                for contextId in cfgTree.getAttrValue('matching-snmp-context-id-list', *pluginCfgPath, **dict(vector=True)):
                    for contentId in cfgTree.getAttrValue('matching-snmp-content-id-list', *pluginCfgPath, **dict(vector=True)):
                        k = credId, contextId, peerId, contentId
                        if k in pluginIdMap:
                            log.error('duplicate snmp-credentials-id %s, snmp-context-id %s, snmp-peer-id %s, snmp-content-id %s at plugin-id(s) %s' % (credId, contextId, peerId, contentId, ','.join(pluginIdList)))
                            return
                        else:
                            log.info('configuring plugin(s) %s (at %s), composite key: %s' % (','.join(pluginIdList), '.'.join(pluginCfgPath), '/'.join(k)))

                            for pluginId in pluginIdList:
                                if not pluginManager.hasPlugin(pluginId):
                                    log.error('undefined plugin ID %s referenced at %s' % (pluginId, '.'.join(pluginCfgPath)))
                                    return

                            pluginIdMap[k] = pluginIdList

    for routeCfgPath in cfgTree.getPathsToAttr('using-trunk-id-list'):
        trunkIdList = cfgTree.getAttrValue('using-trunk-id-list', *routeCfgPath, **dict(vector=True))
        log.info('configuring destination trunk ID(s) %s (at %s)...' % (','.join(trunkIdList), '.'.join(routeCfgPath)))
        for credId in cfgTree.getAttrValue('matching-snmp-credentials-id-list', *routeCfgPath, **dict(vector=True)):
            for peerId in cfgTree.getAttrValue('matching-snmp-peer-id-list', *routeCfgPath, **dict(vector=True)):
                for contextId in cfgTree.getAttrValue('matching-snmp-context-id-list', *routeCfgPath, **dict(vector=True)):
                    for contentId in cfgTree.getAttrValue('matching-snmp-content-id-list', *routeCfgPath, **dict(vector=True)):
                        k = credId, contextId, peerId, contentId
                        if k in trunkIdMap:
                            log.error('duplicate snmp-credentials-id %s, snmp-context-id %s, snmp-peer-id %s, snmp-content-id %s at trunk-id(s) %s' % (credId, contextId, peerId, contentId, ','.join(trunkIdList)))
                            return
                        else:
                            trunkIdMap[k] = trunkIdList

                        log.info('configuring trunk routing to %s (at %s), composite key: %s' % (','.join(trunkIdList), '.'.join(routeCfgPath), '/'.join(k)))

    def dataCbFun(trunkId, msgId, msg):
        log.debug('message ID %s received from trunk %s' % (msgId, trunkId))

    trunkingManager = TrunkingManager(dataCbFun)

    for trunkCfgPath in cfgTree.getPathsToAttr('trunk-id'):
        trunkId = cfgTree.getAttrValue('trunk-id', *trunkCfgPath)
        secret = cfgTree.getAttrValue('trunk-crypto-key', *trunkCfgPath, **dict(default=''))
        secret = secret and (secret*((16//len(secret))+1))[:16]
        log.info('configuring trunk ID %s (at %s)...' % (trunkId, '.'.join(trunkCfgPath)))
        connectionMode = cfgTree.getAttrValue('trunk-connection-mode', *trunkCfgPath)
        if connectionMode == 'client':
            trunkingManager.addClient(
                trunkId,
                parseTrunkEndpoint(cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath)),
                parseTrunkEndpoint(cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath), 30201),
                cfgTree.getAttrValue('trunk-ping-period', *trunkCfgPath, default=0, expect=int),
                secret
            )
            log.info('new trunking client from %s to %s' % (cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath), cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath)))
        if connectionMode == 'server':
            trunkingManager.addServer(
                parseTrunkEndpoint(cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath), 30201),
                cfgTree.getAttrValue('trunk-ping-period', *trunkCfgPath, default=0, expect=int),
                secret
            )
            log.info('new trunking server at %s' % (cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath)))

    transportDispatcher.registerTimerCbFun(
        trunkingManager.setupTrunks, random.randrange(1, 5)
    )
    transportDispatcher.registerTimerCbFun(
        trunkingManager.monitorTrunks, random.randrange(1, 5)
    )

    try:
        daemon.dropPrivileges(procUser, procGroup)

    except Exception:
        log.error('can not drop privileges: %s' % sys.exc_info()[1])
        return

    if not foregroundFlag:
        try:
            daemon.daemonize(pidFile)

        except Exception:
            log.error('can not daemonize process: %s' % sys.exc_info()[1])
            return

    # Run mainloop

    log.info('starting I/O engine...')

    transportDispatcher.jobStarted(1)  # server job would never finish

    # Python 2.4 does not support the "finally" clause

    while True:
        try:
            transportDispatcher.runDispatcher()

        except (PySnmpError, SnmpfwdError, socket.error):
            log.error(str(sys.exc_info()[1]))
            continue

        except Exception:
            transportDispatcher.closeDispatcher()
            raise


if __name__ == '__main__':
    rc = 1

    try:
        main()

    except KeyboardInterrupt:
        log.info('shutting down process...')
        rc = 0

    except Exception:
        for line in traceback.format_exception(*sys.exc_info()):
            log.error(line.replace('\n', ';'))

    log.info('process terminated')

    sys.exit(rc)
