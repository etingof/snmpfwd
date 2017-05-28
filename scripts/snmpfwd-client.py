#!/usr/bin/env python
#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
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
from pysnmp.entity.rfc3413 import config as lcd
from pysnmp.entity.rfc3413 import cmdgen, ntforg, context
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
from pysnmp.proto import rfc1157, rfc1902, rfc1905, rfc3411
from pysnmp.proto.api import v2c
from pyasn1 import debug as pyasn1_debug
from pysnmp import debug as pysnmp_debug
from snmpfwd import macro
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, daemon, cparser
from snmpfwd.plugins.manager import PluginManager
from snmpfwd.plugins import status
from snmpfwd.trunking.manager import TrunkingManager

# Settings
PROGRAM_NAME = 'snmpfwd-client'
CONFIG_FILE = '/usr/local/etc/snmpfwd/client.cfg'
CONFIG_VERSION = '2'
PLUGIN_API_VERSION = 2

authProtocols = {
  'MD5': config.usmHMACMD5AuthProtocol,
  'SHA': config.usmHMACSHAAuthProtocol,
  'NONE': config.usmNoAuthProtocol
}

privProtocols = {
  'DES': config.usmDESPrivProtocol,
  '3DES': config.usm3DESEDEPrivProtocol,
  'AES': config.usmAesCfb128Protocol,
  'AES128': config.usmAesCfb128Protocol,
  'AES192': config.usmAesCfb192Protocol,
  'AES256': config.usmAesCfb256Protocol,
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
            '|'.join(log.methodsMap),
            '|'.join(log.levelsMap)
        )

    log.setLogger(PROGRAM_NAME, 'stderr')

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

    for opt in opts:
        if opt[0] == '-h' or opt[0] == '--help':
            sys.stderr.write("""\
    Synopsis:
      SNMP Proxy Forwarder: client part. Receives SNMP PDUs via one or many
      encrypted trunks established with the Forwarder's Agent part(s) running
      elsewhere and routes PDUs to built-in SNMP Managers for further
      transmission towards SNMP Agents.
      Can implement complex routing and protocol conversion logic through
      analyzing parts of SNMP messages and matching them against proxying rules.

    Documentation:
      http://snmpfwd.sourceforge.io/

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
    Software documentation and support at https://github.com/etingof/snmpfwd
    %s
    """ % (snmpfwd.__version__, hasattr(pysnmp, '__version__') and pysnmp.__version__ or 'unknown', hasattr(pyasn1, '__version__') and pyasn1.__version__ or 'unknown', sys.version, helpMessage))
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
            try:
                log.setLogger(PROGRAM_NAME, *opt[1].split(':'), **dict(force=True))
            except SnmpfwdError:
                sys.stderr.write('%s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
                return
        elif opt[0] == '--log-level':
            try:
                log.setLevel(opt[1])
            except SnmpfwdError:
                sys.stderr.write('%s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
                return
        elif opt[0] == '--config-file':
            cfgFile = opt[1]

    try:
        cfgTree = cparser.Config().load(cfgFile)

    except SnmpfwdError:
        sys.stderr.write('ERROR: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
        return

    if cfgTree.getAttrValue('program-name', '', default=None) != PROGRAM_NAME:
        log.error('config file %s does not match program name %s' % (cfgFile, PROGRAM_NAME))
        return

    if cfgTree.getAttrValue('config-version', '', default=None) != CONFIG_VERSION:
        log.error('config file %s version is not compatible with program version %s' % (cfgFile, CONFIG_VERSION))
        return

    random.seed()

    #
    # SNMPv3 CommandGenerator & NotificationOriginator implementation
    #

    commandGenerator = cmdgen.CommandGenerator()

    notificationOriginator = ntforg.NotificationOriginator()

    origCredIdList = []
    srvClassIdList = []
    peerIdMap = {}
    pluginIdMap = {}
    routingMap = {}
    engineIdMap = {}

    transportDispatcher = AsynsockDispatcher()
    transportDispatcher.registerRoutingCbFun(lambda td, t, d: td)
    transportDispatcher.setSocketMap()  # use global asyncore socket map

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

    for peerEntryPath in cfgTree.getPathsToAttr('snmp-peer-id'):
        peerId = cfgTree.getAttrValue('snmp-peer-id', *peerEntryPath)
        if peerId in peerIdMap:
            log.error('duplicate snmp-peer-id=%s at %s' % (peerId, '.'.join(peerEntryPath)))
            return

        log.info('configuring SNMP peer %s (at %s)...' % (peerId, '.'.join(peerEntryPath)))

        engineId = cfgTree.getAttrValue('snmp-engine-id', *peerEntryPath)
        if engineId in engineIdMap:
            snmpEngine, snmpContext, snmpEngineMap = engineIdMap[engineId]
            log.info('using engine-id: %s' % snmpEngine.snmpEngineID.prettyPrint())
        else:
            snmpEngine = engine.SnmpEngine(snmpEngineID=engineId)
            snmpContext = context.SnmpContext(snmpEngine)
            snmpEngineMap = {
                'transportDomain': {},
                'securityName': {},
                'credIds': set()
            }

            engineIdMap[engineId] = snmpEngine, snmpContext, snmpEngineMap

            log.info('new engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())

        transportOptions = cfgTree.getAttrValue('snmp-transport-options', *peerEntryPath, **dict(default=[], vector=True))

        bindAddrMacro = None
        bindAddr = cfgTree.getAttrValue('snmp-bind-address', *peerEntryPath)

        if 'transparent-proxy' in transportOptions or 'virtual-interface' in transportOptions:
            if '$' in bindAddr:
                bindAddrMacro = bindAddr
                bindAddr = '0.0.0.0', 0
            else:
                try:
                    if ':' in bindAddr:
                        bindAddr = bindAddr.split(':', 1)
                        bindAddr = bindAddr[0], int(bindAddr[1])
                    else:
                        bindAddr = bindAddr, 0

                except (ValueError, IndexError):
                    log.error('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(peerEntryPath)))
                    return
        else:
            try:
                if ':' in bindAddr:
                    bindAddr = bindAddr.split(':', 1)
                    bindAddr = bindAddr[0], int(bindAddr[1])
                else:
                    bindAddr = bindAddr, 0

            except (ValueError, IndexError):
                log.error('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(peerEntryPath)))
                exit(-1)

        transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *peerEntryPath)
        transportDomain = rfc1902.ObjectName(str(transportDomain))

        if transportDomain in snmpEngineMap['transportDomain']:
            log.info('using transport endpoint with transport ID %s' % (transportDomain,))
        else:
            if transportDomain[:len(udp.domainName)] == udp.domainName:
                transport = udp.UdpTransport()
            elif transportDomain[:len(udp6.domainName)] == udp6.domainName:
                transport = udp6.Udp6Transport()
            else:
                log.error('unknown transport domain %s' % (transportDomain,))
                return

            snmpEngine.registerTransportDispatcher(
                transportDispatcher, transportDomain
            )

            t = transport.openClientMode(bindAddr)

            if 'transparent-proxy' in transportOptions:
                t.enablePktInfo()
                t.enableTransparent()
            elif 'virtual-interface' in transportOptions:
                t.enablePktInfo()

            config.addSocketTransport(snmpEngine, transportDomain, t)

            snmpEngineMap['transportDomain'][transportDomain] = bindAddr[0], bindAddr[1], transportDomain
            log.info('new transport endpoint at bind address %s:%s, options %s, transport ID %s' % (bindAddr[0], bindAddr[1], transportOptions and '/'.join(transportOptions) or '<none>', transportDomain))

        securityModel = cfgTree.getAttrValue('snmp-security-model', *peerEntryPath)
        securityModel = rfc1902.Integer(securityModel)
        securityLevel = cfgTree.getAttrValue('snmp-security-level', *peerEntryPath)
        securityLevel = rfc1902.Integer(securityLevel)
        securityName = cfgTree.getAttrValue('snmp-security-name', *peerEntryPath)

        contextEngineId = cfgTree.getAttrValue('snmp-context-engine-id', *peerEntryPath, **dict(default=None))
        contextName = cfgTree.getAttrValue('snmp-context-name', *peerEntryPath, **dict(default=''))

        if securityModel in (1, 2):
            if securityName in snmpEngineMap['securityName']:
                if snmpEngineMap['securityName'][securityName] == securityModel:
                    log.info('using security-name %s' % securityName)
                else:
                    log.error('security-name %s already in use at security-model %s' % (securityName, securityModel))
                    sys.exit(1)
            else:
                communityName = cfgTree.getAttrValue('snmp-community-name', *peerEntryPath)
                config.addV1System(snmpEngine, securityName, communityName,
                                   securityName=securityName)

                log.info('new community-name %s, security-model %s, security-name %s, security-level %s' % (communityName, securityModel, securityName, securityLevel))
                snmpEngineMap['securityName'][securityName] = securityModel

        elif securityModel == 3:
            if securityName in snmpEngineMap['securityName']:
                if snmpEngineMap['securityName'][securityName] == securityModel:
                    log.info('using USM security-name: %s' % securityName)
                else:
                    raise SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
            else:
                usmUser = cfgTree.getAttrValue('snmp-usm-user', *peerEntryPath)
                log.info('new USM user %s, security-model %s, security-level %s, security-name %s' % (usmUser, securityModel, securityLevel, securityName))

                if securityLevel in (2, 3):
                    usmAuthProto = cfgTree.getAttrValue('snmp-usm-auth-protocol', *peerEntryPath, **dict(default=config.usmHMACMD5AuthProtocol))
                    usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                    usmAuthKey = cfgTree.getAttrValue('snmp-usm-auth-key', *peerEntryPath)
                    log.info('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                    if securityLevel == 3:
                        usmPrivProto = cfgTree.getAttrValue('snmp-usm-priv-protocol', *peerEntryPath, **dict(default=config.usmDESPrivProtocol))
                        usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                        usmPrivKey = cfgTree.getAttrValue('snmp-usm-priv-key', *peerEntryPath, **dict(default=None))
                        log.info('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))

                        config.addV3User(
                            snmpEngine, usmUser,
                            usmAuthProto, usmAuthKey,
                            usmPrivProto, usmPrivKey
                        )

                    else:
                        config.addV3User(snmpEngine, usmUser, usmAuthProto, usmAuthKey)

                else:
                    config.addV3User(snmpEngine, usmUser)

                snmpEngineMap['securityName'][securityName] = securityModel

        else:
            log.error('unknown security-model: %s' % securityModel)
            sys.exit(1)

        credId = '/'.join([str(x) for x in (securityName, securityLevel, securityModel)])
        if credId in snmpEngineMap['credIds']:
            log.info('using credentials ID %s...' % credId)
        else:
            config.addTargetParams(
                snmpEngine, credId, securityName, securityLevel,
                securityModel == 3 and 3 or securityModel-1
            )
            log.info('new credentials %s, security-name %s, security-level %s, security-model %s' % (credId, securityName, securityLevel, securityModel))
            snmpEngineMap['credIds'].add(credId)

        peerAddrMacro = None
        peerAddr = cfgTree.getAttrValue('snmp-peer-address', *peerEntryPath)

        if 'transparent-proxy' in transportOptions or 'virtual-interface' in transportOptions:
            if '$' in peerAddr:
                peerAddrMacro = peerAddr
                peerAddr = '0.0.0.0', 0
            else:
                try:
                    peerAddr = peerAddr.split(':', 1)
                    peerAddr = peerAddr[0], int(peerAddr[1])
                except (ValueError, IndexError):
                    log.error('bad snmp-peer-address specification %s at %s' % (peerAddr, '.'.join(peerEntryPath)))
                    return
        else:
            try:
                peerAddr = peerAddr.split(':', 1)
                peerAddr = peerAddr[0], int(peerAddr[1])
            except (ValueError, IndexError):
                log.error('bad snmp-peer-address specification %s at %s' % (peerAddr, '.'.join(peerEntryPath)))
                return

        timeout = cfgTree.getAttrValue('snmp-peer-timeout', *peerEntryPath)
        retries = cfgTree.getAttrValue('snmp-peer-retries', *peerEntryPath)

        config.addTargetAddr(
            snmpEngine, peerId, transportDomain, peerAddr, credId, timeout, retries
        )

        peerIdMap[peerId] = snmpEngine, contextEngineId, contextName, bindAddr, bindAddrMacro, peerAddr, peerAddrMacro

        log.info('new peer ID %s, bind address %s, peer address %s, timeout %s, retries %s, credentials ID %s' % (peerId, bindAddrMacro or '<default>', peerAddrMacro or '%s:%s' % peerAddr, timeout, retries, credId))

    duplicates = {}

    for origCredCfgPath in cfgTree.getPathsToAttr('orig-snmp-peer-id'):
        origCredId = cfgTree.getAttrValue('orig-snmp-peer-id', *origCredCfgPath)
        if origCredId in duplicates:
            log.error('duplicate orig-snmp-peer-id=%s at %s and %s' % (origCredId, '.'.join(origCredCfgPath), '.'.join(duplicates[origCredId])))
            return

        duplicates[origCredId] = origCredCfgPath

        k = '#'.join(
            (cfgTree.getAttrValue('orig-snmp-engine-id-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-transport-domain-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-peer-address-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-bind-address-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-security-model-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-security-level-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-security-name-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-context-engine-id-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-context-name-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-pdu-type-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('orig-snmp-oid-prefix-pattern', *origCredCfgPath))
        )

        log.info('configuring original SNMP peer ID %s (at %s), composite key: %s' % (origCredId, '.'.join(origCredCfgPath), k))

        origCredIdList.append((origCredId, re.compile(k)))

    duplicates = {}

    for srvClassCfgPath in cfgTree.getPathsToAttr('server-classification-id'):
        srvClassId = cfgTree.getAttrValue('server-classification-id', *srvClassCfgPath)
        if srvClassId in duplicates:
            log.error('duplicate server-classification-id=%s at %s and %s' % (srvClassId, '.'.join(srvClassCfgPath), '.'.join(duplicates[srvClassId])))
            return

        duplicates[srvClassId] = srvClassCfgPath

        k = '#'.join(
            (cfgTree.getAttrValue('server-snmp-credentials-id-pattern', *srvClassCfgPath),
             cfgTree.getAttrValue('server-snmp-context-id-pattern', *srvClassCfgPath),
             cfgTree.getAttrValue('server-snmp-content-id-pattern', *srvClassCfgPath),
             cfgTree.getAttrValue('server-snmp-peer-id-pattern', *srvClassCfgPath))
        )

        log.info('configuring server classification ID %s (at %s), composite key: %s' % (srvClassId, '.'.join(srvClassCfgPath), k))

        srvClassIdList.append((srvClassId, re.compile(k)))

    del duplicates

    for pluginCfgPath in cfgTree.getPathsToAttr('using-plugin-id-list'):
        pluginIdList = cfgTree.getAttrValue('using-plugin-id-list', *pluginCfgPath, **dict(vector=True))
        log.info('configuring plugin ID(s) %s (at %s)...' % (','.join(pluginIdList), '.'.join(pluginCfgPath)))
        for credId in cfgTree.getAttrValue('matching-orig-snmp-peer-id-list', *pluginCfgPath, **dict(vector=True)):
            for srvClassId in cfgTree.getAttrValue('matching-server-classification-id-list', *pluginCfgPath, **dict(vector=True)):
                for trunkId in cfgTree.getAttrValue('matching-trunk-id-list', *pluginCfgPath, **dict(vector=True)):
                    k = credId, srvClassId, trunkId
                    if k in pluginIdMap:
                        log.error('duplicate snmp-credentials-id=%s and server-classification-id=%s and trunk-id=%s at plugin-id %s' % (credId, srvClassId, trunkId, ','.join(pluginIdList)))
                        return
                    else:
                        log.info('configuring plugin(s) %s (at %s), composite key: %s' % (','.join(pluginIdList), '.'.join(pluginCfgPath), '/'.join(k)))

                        for pluginId in pluginIdList:
                            if not pluginManager.hasPlugin(pluginId):
                                log.error('undefined plugin ID %s referenced at %s' % (pluginId, '.'.join(pluginCfgPath)))
                                return

                        pluginIdMap[k] = pluginIdList

    for routeCfgPath in cfgTree.getPathsToAttr('using-snmp-peer-id-list'):
        peerIdList = cfgTree.getAttrValue('using-snmp-peer-id-list', *routeCfgPath, **dict(vector=True))
        log.info('configuring routing entry with peer IDs %s (at %s)...' % (','.join(peerIdList), '.'.join(routeCfgPath)))
        for credId in cfgTree.getAttrValue('matching-orig-snmp-peer-id-list', *routeCfgPath, **dict(vector=True)):
            for srvClassId in cfgTree.getAttrValue('matching-server-classification-id-list', *routeCfgPath, **dict(vector=True)):
                for trunkId in cfgTree.getAttrValue('matching-trunk-id-list', *routeCfgPath, **dict(vector=True)):
                    k = credId, srvClassId, trunkId
                    if k in routingMap:
                        log.error('duplicate snmp-credentials-id=%s and server-classification-id=%s and trunk-id=%s at snmp-peer-id %s' % (credId, srvClassId, trunkId, ','.join(peerIdList)))
                        return
                    else:
                        for peerId in peerIdList:
                            if peerId not in peerIdMap:
                                log.error('missing peer-id %s at %s' % (peerId, '.'.join(routeCfgPath)))
                                return

                        routingMap[k] = peerIdList

    def prettyVarBinds(pdu):
        return not pdu and '<none>' or ';'.join(['%s:%s' % (vb[0].prettyPrint(), vb[1].prettyPrint()) for vb in v2c.apiPDU.getVarBinds(pdu)])

    def __rspCbFun(snmpEngine, sendRequestHandle, errorIndication, rspPDU, cbCtx):
        trunkId, msgId, trunkReq, pluginIdList, snmpReqInfo, reqCtx = cbCtx

        trunkRsp = {}

        if errorIndication:
            log.info('SNMP error returned for message ID %s received from trunk %s: %s' % (msgId, trunkId, errorIndication))
            trunkRsp['error-indication'] = errorIndication

        reqPdu = trunkReq['snmp-pdu']

        if rspPDU:
            for pluginId in pluginIdList:
                if reqPdu.tagSet in rfc3411.notificationClassPDUs:
                    st, rspPDU = pluginManager.processNotificationResponse(
                        pluginId, snmpEngine, rspPDU, snmpReqInfo, reqCtx
                    )

                elif reqPdu.tagSet not in rfc3411.unconfirmedClassPDUs:
                    st, rspPDU = pluginManager.processCommandResponse(
                        pluginId, snmpEngine, rspPDU, snmpReqInfo, reqCtx
                    )
                else:
                    log.error('ignoring unsupported PDU')
                    break

                if st == status.BREAK:
                    break

                elif st == status.DROP:
                    log.debug('received SNMP %s message, snmp-var-binds=%s, plugin %s muted response' % (errorIndication and 'error' or 'response', prettyVarBinds(rspPDU), pluginId))
                    trunkRsp['snmp-pdu'] = None

                    try:
                        trunkingManager.sendRsp(trunkId, msgId, trunkRsp)

                    except SnmpfwdError:
                        log.error('trunk message not sent: %s' % sys.exc_info()[1])

                    return

        trunkRsp['snmp-pdu'] = rspPDU

        log.debug('received SNMP %s message, sending trunk message #%s to trunk %s, original SNMP peer address %s:%s received at %s:%s, var-binds: %s' % (errorIndication and 'error' or 'response', msgId, trunkId, trunkReq['snmp-peer-address'], trunkReq['snmp-peer-port'], trunkReq['snmp-bind-address'], trunkReq['snmp-bind-port'], prettyVarBinds(rspPDU)))

        try:
            trunkingManager.sendRsp(trunkId, msgId, trunkRsp)

        except SnmpfwdError:
            log.error('trunk message not sent: %s' % sys.exc_info()[1])

    #
    # The following needs proper support in pysnmp. Meanwhile - monkey patching!
    #

    q = []

    origGetTargetAddr = lcd.getTargetAddr

    def getTargetAddr(snmpEngine, snmpTargetAddrName):
        r = list(origGetTargetAddr(snmpEngine, snmpTargetAddrName))
        if q:
            r[1] = r[1].__class__(q[1]).setLocalAddress(q[0])
            q.pop()
            q.pop()
        return r

    lcd.getTargetAddr = getTargetAddr

    def dataCbFun(trunkId, msgId, msg):
        k = [str(x) for x in (msg['snmp-engine-id'],
                              msg['snmp-transport-domain'],
                              msg['snmp-peer-address'] + ':' + str(msg['snmp-peer-port']),
                              msg['snmp-bind-address'] + ':' + str(msg['snmp-bind-port']),
                              msg['snmp-security-model'],
                              msg['snmp-security-level'],
                              msg['snmp-security-name'],
                              msg['snmp-context-engine-id'],
                              msg['snmp-context-name'])]
        k.append(snmpPduTypesMap.get(msg['snmp-pdu'].tagSet, '?'))
        k.append('|'.join([str(x[0]) for x in v2c.apiPDU.getVarBinds(msg['snmp-pdu'])]))
        k = '#'.join(k)

        for x, y in origCredIdList:
            if y.match(k):
                origPeerId = macro.expandMacro(x, msg)
                break
        else:
            origPeerId = None

        k = [str(x) for x in (msg['server-snmp-credentials-id'],
                              msg['server-snmp-context-id'],
                              msg['server-snmp-content-id'],
                              msg['server-snmp-peer-id'])]
        k = '#'.join(k)

        for x, y in srvClassIdList:
            if y.match(k):
                srvClassId = macro.expandMacro(x, msg)
                break
        else:
            srvClassId = None

        errorIndication = None

        pluginIdList = pluginIdMap.get((origPeerId, srvClassId, macro.expandMacro(trunkId, msg)))

        peerIdList = routingMap.get((origPeerId, srvClassId, macro.expandMacro(trunkId, msg)))
        if not peerIdList:
            log.error('unroutable trunk message #%s from trunk %s, srv-classification-id %s, orig-peer-id %s (original SNMP info: %s)' % (msgId, trunkId, srvClassId, origPeerId or '<none>', ', '.join([x == 'snmp-pdu' and 'snmp-var-binds=%s' % prettyVarBinds(msg['snmp-pdu']) or '%s=%s' % (x, msg[x].prettyPrint()) for x in msg])))
            errorIndication = 'no route to SNMP peer configured'

        cbCtx = trunkId, msgId, msg, (), {}, {}

        if errorIndication:
            __rspCbFun(None, None, errorIndication, None, cbCtx)
            return

        log.debug('received trunk message #%s from trunk %s' % (msgId, trunkId))

        for peerId in peerIdList:
            peerId = macro.expandMacro(peerId, msg)

            (snmpEngine,
             contextEngineId,
             contextName,
             bindAddr,
             bindAddrMacro,
             peerAddr,
             peerAddrMacro) = peerIdMap[peerId]

            if bindAddrMacro:
                bindAddr = macro.expandMacro(bindAddrMacro, msg), 0
            if bindAddr:
                q.append(bindAddr)

            if peerAddrMacro:
                peerAddr = macro.expandMacro(peerAddrMacro, msg), 161
            if peerAddr:
                q.append(peerAddr)

            logMsg = 'SNMP message to peer ID %s, bind-address %s, peer-address %s (original SNMP info: %s; original server classification: %s)' % (peerId, bindAddr[0] or '<default>', peerAddr[0] or '<default>', ', '.join([x == 'snmp-pdu' and 'snmp-var-binds=%s' % prettyVarBinds(msg['snmp-pdu']) or '%s=%s' % (x, msg[x].prettyPrint()) for x in msg if x.startswith('snmp-')]), ' '.join(['%s=%s' % (x, msg[x].prettyPrint()) for x in msg if x.startswith('server-')]))

            log.debug('sending %s' % logMsg)

            pdu = msg['snmp-pdu']

            if pluginIdList:
                snmpReqInfo = msg.copy()
                reqCtx = {}

                cbCtx = trunkId, msgId, msg, pluginIdList, snmpReqInfo, reqCtx

                for pluginNum, pluginId in enumerate(pluginIdList):

                    if pdu.tagSet in rfc3411.notificationClassPDUs:
                        st, pdu = pluginManager.processNotificationRequest(
                            pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx
                        )

                    elif pdu.tagSet not in rfc3411.unconfirmedClassPDUs:
                        st, pdu = pluginManager.processCommandRequest(
                            pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx
                        )

                    else:
                        log.error('ignoring unsupported PDU')
                        break

                    if st == status.BREAK:
                        cbCtx = trunkId, msgId, msg, pluginIdList[:pluginNum], snmpReqInfo, reqCtx
                        break

                    elif st == status.DROP:
                        log.debug('plugin %s muted request %s' % (pluginId, logMsg))
                        __rspCbFun(snmpEngine, None, None, None, cbCtx)
                        break

                    elif st == status.RESPOND:
                        log.debug('plugin %s forced immediate response to %s' % (pluginId, logMsg))
                        __rspCbFun(snmpEngine, None, None, pdu, cbCtx)
                        break

            if pdu.tagSet in rfc3411.notificationClassPDUs:
                if pdu.tagSet in rfc3411.unconfirmedClassPDUs:
                    notificationOriginator.sendPdu(
                        snmpEngine,
                        peerId,
                        macro.expandMacro(contextEngineId, msg),
                        macro.expandMacro(contextName, msg),
                        pdu
                    )

                    # respond to trunk right away
                    __rspCbFun(snmpEngine, None, errorIndication, None, cbCtx)

                else:
                    notificationOriginator.sendPdu(
                        snmpEngine,
                        peerId,
                        macro.expandMacro(contextEngineId, msg),
                        macro.expandMacro(contextName, msg),
                        pdu,
                        __rspCbFun,
                        cbCtx
                    )

            elif pdu.tagSet not in rfc3411.unconfirmedClassPDUs:
                commandGenerator.sendPdu(
                    snmpEngine,
                    peerId,
                    macro.expandMacro(contextEngineId, msg),
                    macro.expandMacro(contextName, msg),
                    pdu,
                    __rspCbFun,
                    cbCtx
                )

            else:
                log.error('ignoring unsupported PDU')

    trunkingManager = TrunkingManager(dataCbFun)

    def getTrunkAddr(a, port=0):
        f = lambda h, p=port: (h, int(p))
        try:
            return f(*a.split(':'))
        except Exception:
            raise SnmpfwdError('improper IPv4 endpoint %s' % a)

    for trunkCfgPath in cfgTree.getPathsToAttr('trunk-id'):
        trunkId = cfgTree.getAttrValue('trunk-id', *trunkCfgPath)
        secret = cfgTree.getAttrValue('trunk-crypto-key', *trunkCfgPath, **dict(default=''))
        secret = secret and (secret*((16//len(secret))+1))[:16]
        log.info('configuring trunk ID %s (at %s)...' % (trunkId, '.'.join(trunkCfgPath)))
        connectionMode = cfgTree.getAttrValue('trunk-connection-mode', *trunkCfgPath)
        if connectionMode == 'client':
            trunkingManager.addClient(
                trunkId,
                getTrunkAddr(cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath)),
                getTrunkAddr(cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath), 30201),
                cfgTree.getAttrValue('trunk-ping-period', *trunkCfgPath, default=0, expect=int),
                secret
            )
            log.info('new trunking client from %s to %s' % (cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath), cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath)))
        if connectionMode == 'server':
            trunkingManager.addServer(
                getTrunkAddr(cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath), 30201),
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
        sys.stderr.write('ERROR: cant drop privileges: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
        return

    if not foregroundFlag:
        try:
            daemon.daemonize(pidFile)

        except Exception:
            sys.stderr.write('ERROR: cant daemonize process: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
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
