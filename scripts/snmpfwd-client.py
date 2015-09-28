#!/usr/bin/env python
#
# SNMP Proxy Forwarder: SNMP client part
#
# Written by Ilya Etingof <ilya@snmplabs.com>, 2015.  All rights reserved.
#
import os
import stat
import sys
import getopt
import traceback
import random
import re
import socket
from pyasn1.codec.ber import encoder, decoder
from pyasn1.compat.octets import str2octs
from pyasn1.error import PyAsn1Error
from pysnmp.error import PySnmpError
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import config as lcd
from pysnmp.entity.rfc3413 import cmdgen, context
from pysnmp.entity.rfc3413.config import getTargetInfo
from pysnmp.proto.error import StatusInformation
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
from pysnmp.smi import exval, indices
from pysnmp.smi.error import MibOperationError
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.proto.api import v2c
from pysnmp import error
from pyasn1 import debug as pyasn1_debug
from pysnmp import debug as pysnmp_debug
from snmpfwd import macro
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, daemon, cparser
from snmpfwd.trunking.manager import TrunkingManager

# Settings
programName = 'snmpfwd-client'
configVersion = '2'
pidFile = ''
cfgFile = '/usr/local/etc/snmpfwd/client.cfg'
foregroundFlag = True
procUser = procGroup = None

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
  rfc1905.ResponsePDU.tagSet: 'RESPONSE'
}

# main script body starts here

helpMessage = """\
Usage: %s [--help]
    [--version ]
    [--debug-snmp=<%s>]
    [--debug-asn1=<%s>]
    [--daemonize]
    [--process-user=<uname>] [--process-group=<gname>]
    [--pid-file=<file>]
    [--logging-method=<%s[:args>]>]
    [--config-file=<file>]""" % (
        sys.argv[0],
        '|'.join([ x for x in pysnmp_debug.flagMap.keys() if x != 'mibview' ]),
        '|'.join([ x for x in pyasn1_debug.flagMap.keys() ]),
        '|'.join(log.gMap.keys())
    )

try:
    opts, params = getopt.getopt(sys.argv[1:], 'hv', [
        'help', 'version', 'debug=', 'debug-snmp=', 'debug-asn1=', 'daemonize',
        'process-user=', 'process-group=', 'pid-file=', 'logging-method=', 
        'config-file='
    ])
except Exception:
    sys.stderr.write('ERROR: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
    sys.exit(-1)

if params:
    sys.stderr.write('ERROR: extra arguments supplied %s\r\n%s\r\n' % (params, helpMessage))
    sys.exit(-1)

v3Args = []

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
  http://snmpfwd.sourceforge.net/
%s
""" % helpMessage)
        sys.exit(-1)
    if opt[0] == '-v' or opt[0] == '--version':
        import snmpfwd, pysnmp, pyasn1
        sys.stderr.write("""\
SNMP Proxy Forwarder version %s, written by Ilya Etingof <ilya@snmplabs.com>
Using foundation libraries: pysnmp %s, pyasn1 %s.
Python interpreter: %s
Software documentation and support at http://snmpfwd.sf.net
%s
""" % (snmpfwd.__version__, hasattr(pysnmp, '__version__') and pysnmp.__version__ or 'unknown', hasattr(pyasn1, '__version__') and pyasn1.__version__ or 'unknown', sys.version, helpMessage))
        sys.exit(-1)
    elif opt[0] == '--debug-snmp':
        pysnmp_debug.setLogger(pysnmp_debug.Debug(*opt[1].split(','), **dict(loggerName=programName+'.pysnmp')))
    elif opt[0] == '--debug-asn1':
        pyasn1_debug.setLogger(pyasn1_debug.Debug(*opt[1].split(','), **dict(loggerName=programName+'.pyasn1')))
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
            log.setLogger(programName, *opt[1].split(':'), **dict(force=True))
        except SnmpfwdError:
            sys.stderr.write('%s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
            sys.exit(-1)
    elif opt[0] == '--config-file':
        cfgFile = opt[1]

log.setLogger(programName, 'stderr')

try:
    cfgTree = cparser.Config().load(cfgFile)
except SnmpfwdError:
    sys.stderr.write('ERROR: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
    sys.exit(-1)

if cfgTree.getAttrValue('program-name', '', default=None) != programName:
    log.msg('ERROR: config file %s does not match program name %s' % (cfgFile, programName))
    sys.exit(-1)

if cfgTree.getAttrValue('config-version', '', default=None) != configVersion:
    log.msg('ERROR: config file %s version is not compatible with program version %s' % (cfgFile, configVersion))
    sys.exit(-1)

random.seed()

#
# SNMPv3 CommandGenerator implementation
#

gCurrentRequestContext = {}

commandGenerator = cmdgen.CommandGenerator()

origCredIdList = []
peerIdMap = {}
routingMap = {}
engineIdMap = {}

transportDispatcher = AsynsockDispatcher()
transportDispatcher.registerRoutingCbFun(lambda td,t,d: td)
transportDispatcher.setSocketMap()  # use global asyncore socket map

for peerEntryPath in cfgTree.getPathsToAttr('snmp-peer-id'):
    peerId = cfgTree.getAttrValue('snmp-peer-id', *peerEntryPath)
    if peerId in peerIdMap:
        log.msg('duplicate snmp-peer-id=%s at %s' % (peerId, '.'.join(peerEntryPath)))
        sys.exit(-1)

    log.msg('configuring SNMP peer %s (at %s)...' % (peerId, '.'.join(peerEntryPath)))

    engineId = cfgTree.getAttrValue('snmp-engine-id', *peerEntryPath)
    if engineId in engineIdMap:
        snmpEngine, snmpContext, snmpEngineMap = engineIdMap[engineId]
        log.msg('using engine-id: %s' % snmpEngine.snmpEngineID.prettyPrint())
    else:
        snmpEngine = engine.SnmpEngine(snmpEngineID=engineId)
        snmpContext = context.SnmpContext(snmpEngine)
        snmpEngineMap = {
            'transportDomain': {},
            'securityName': {},
            'credIds': set()
        }

        engineIdMap[engineId] = snmpEngine, snmpContext, snmpEngineMap

        log.msg('new engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())

    transportOptions = cfgTree.getAttrValue('snmp-transport-options', *peerEntryPath, **dict(default=[], vector=True))

    bindAddrMacro = None
    bindAddr = cfgTree.getAttrValue('snmp-bind-address', *peerEntryPath)

    if 'transparent-proxy' in transportOptions or \
           'virtual-interface' in transportOptions:
        if '$' in bindAddr:
            bindAddrMacro = bindAddr
            bindAddr = '0.0.0.0', 0
        else:
            try:
                bindAddr = bindAddr.split(':',1)
                bindAddr = bindAddr[0], int(bindAddr[1])
            except (ValueError, IndexError):
                log.msg('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(peerEntryPath)))
                exit(-1)
    else:
        try:
            bindAddr = bindAddr.split(':',1)
            bindAddr = bindAddr[0], int(bindAddr[1])
        except (ValueError, IndexError):
            log.msg('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(peerEntryPath)))
            exit(-1)

    transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *peerEntryPath)
    transportDomain = rfc1902.ObjectName(str(transportDomain))

    if transportDomain in snmpEngineMap['transportDomain']:
        log.msg('using transport endpoint with transport ID %s' % (transportDomain,))
    else:
        if transportDomain[:len(udp.domainName)] == udp.domainName:
            transport = udp.UdpTransport()
        elif transportDomain[:len(udp6.domainName)] == udp6.domainName:
            transport = udp6.Udp6Transport()
        else:
            log.msg('unknown transport domain %s' % (transportDomain,))
            sys.exit(-1)

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
        log.msg('new transport endpoint at bind address %s:%s, options %s, transport ID %s' % (bindAddr[0], bindAddr[1], transportOptions and '/'.join(transportOptions) or '<none>', transportDomain))

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
                log.msg('using security-name %s' % securityName)
            else:
                raise error.SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
        else:
            communityName = cfgTree.getAttrValue('snmp-community-name', *peerEntryPath)
            config.addV1System(snmpEngine, securityName, communityName, 
                               securityName=securityName)

            log.msg('new community-name %s, security-model %s, security-name %s, security-level %s' % (communityName, securityModel, securityName, securityLevel))
            snmpEngineMap['securityName'][securityName] = securityModel

    elif securityModel == 3:
        if securityName in snmpEngineMap['securityName']:
            if snmpEngineMap['securityName'][securityName] == securityModel:
                log.msg('using USM security-name: %s' % usmUser)
            else:
                raise error.SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
        else:
            usmUser = cfgTree.getAttrValue('snmp-usm-user', *peerEntryPath)
            log.msg('new USM user %s, security-model %s, security-level %s, security-name %s' % (usmUser, securityModel, securityLevel, securityName))

            if securityLevel in (2, 3):
                usmAuthProto = cfgTree.getAttrValue('snmp-usm-auth-protocol', *peerEntryPath, **dict(default=config.usmHMACMD5AuthProtocol))
                usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                usmAuthKey = cfgTree.getAttrValue('snmp-usm-auth-key', *peerEntryPath)
                log.msg('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                if securityLevel == 3:
                    usmPrivProto = cfgTree.getAttrValue('snmp-usm-priv-protocol', *peerEntryPath, **dict(default=config.usmDESPrivProtocol))
                    usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                    usmPrivKey = cfgTree.getAttrValue('snmp-usm-priv-key', *peerEntryPath, **dict(default=None))
                    log.msg('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))
            snmpEngineMap['securityName'][securityName] = securityModel

        config.addV3User(
            snmpEngine, usmUser,
            usmAuthProto, usmAuthKey,
            usmPrivProto, usmPrivKey
        )

    else:
        raise SnmpfwdError('unknown security-model: %s' % securityModel)

    credId = '/'.join([str(x) for x in (securityName, securityLevel, securityModel)])
    if credId in snmpEngineMap['credIds']:
        log.msg('using credentials ID %s...' % credId)
    else:
        config.addTargetParams(
            snmpEngine, credId, securityName, securityLevel, 
            securityModel == 3 and 3 or securityModel-1
        )
        log.msg('new credentials %s, security-name %s, security-level %s, security-model %s' % (credId, securityName, securityLevel, securityModel)) 
        snmpEngineMap['credIds'].add(credId)

    peerAddrMacro = None
    peerAddr = cfgTree.getAttrValue('snmp-peer-address', *peerEntryPath)

    if 'transparent-proxy' in transportOptions or \
           'virtual-interface' in transportOptions:
        if '$' in peerAddr:
            peerAddrMacro = peerAddr
            peerAddr = '0.0.0.0', 0
        else:
            try:
                peerAddr = peerAddr.split(':',1)
                peerAddr = peerAddr[0], int(peerAddr[1])
            except (ValueError, IndexError):
                log.msg('bad snmp-peer-address specification %s at %s' % (peerAddr, '.'.join(peerEntryPath)))
                exit(-1)
    else:
        try:
            peerAddr = peerAddr.split(':',1)
            peerAddr = peerAddr[0], int(peerAddr[1])
        except (ValueError, IndexError):
            log.msg('bad snmp-peer-address specification %s at %s' % (peerAddr, '.'.join(peerEntryPath)))
            exit(-1)

    timeout = cfgTree.getAttrValue('snmp-peer-timeout', *peerEntryPath)
    retries = cfgTree.getAttrValue('snmp-peer-retries', *peerEntryPath)

    config.addTargetAddr(
        snmpEngine, peerId, transportDomain, peerAddr, credId, timeout, retries
    )

    peerIdMap[peerId] = snmpEngine, contextEngineId, contextName, bindAddr, bindAddrMacro, peerAddr, peerAddrMacro

    log.msg('new peer ID %s, bind address %s, peer address %s, timeout %s, retries %s, credentials ID %s' % (peerId, bindAddrMacro or '<default>', peerAddrMacro or '%s:%s' % peerAddr, timeout, retries, credId))

duplicates = {}

for origCredCfgPath in cfgTree.getPathsToAttr('orig-snmp-peer-id'):
    origCredId = cfgTree.getAttrValue('orig-snmp-peer-id', *origCredCfgPath)
    if origCredId in duplicates:
        log.msg('duplicate orig-snmp-peer-id=%s at %s and %s' % (origCredId, '.'.join(origCredCfgPath), '.'.join(duplicates[origCredId])))
        sys.exit(-1)

    duplicates[origCredId] = origCredCfgPath
    
    k = '#'.join(
        ( cfgTree.getAttrValue('orig-snmp-engine-id-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-transport-domain-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-peer-address-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-bind-address-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-security-model-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-security-level-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-security-name-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-context-engine-id-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-context-name-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-pdu-type-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('orig-snmp-oid-prefix-pattern', *origCredCfgPath) )
    )

    log.msg('configuring original SNMP peer ID %s (at %s), composite key: %r' % (origCredId, '.'.join(origCredCfgPath), k))

    origCredIdList.append((origCredId, re.compile(k)))

del duplicates

for routeCfgPath in cfgTree.getPathsToAttr('using-snmp-peer-id-list'):
    peerIdList = cfgTree.getAttrValue('using-snmp-peer-id-list', *routeCfgPath, **dict(vector=True))
    log.msg('configuring routing entry with peer IDs %s (at %s)...' % (','.join(peerIdList), '.'.join(routeCfgPath)))
    for credId in cfgTree.getAttrValue('matching-orig-snmp-peer-id-list', *routeCfgPath, **dict(vector=True)):
        for trunkId in cfgTree.getAttrValue('matching-trunk-id-list', *routeCfgPath, **dict(vector=True)):
            k = credId, trunkId
            if k in routingMap:
                log.msg('duplicate credentials-id=%s and trunk-id %s at peer-id %s' % (credId, trunkId, ','.join(peerIdList)))
                sys.exit(-1)
            else:
                for peerId in peerIdList:
                    if peerId not in peerIdMap:
                        log.msg('missing peer-id %s at %s' % (peerId, '.'.join(routeCfgPath)))
                        sys.exit(-1)

                routingMap[k] = peerIdList

def prettyVarBinds(pdu):
    return not pdu and '<none>' or ';'.join([ '%s:%s' % (vb[0].prettyPrint(), vb[1].prettyPrint()) for vb in v2c.apiPDU.getVarBinds(pdu) ])

def __rspCbFun(snmpEngine, sendRequestHandle, errorIndication, rspPDU, cbCtx):
    trunkId, msgId, trunkReq = cbCtx
    
    trunkRsp = {}
        
    if errorIndication:
        log.msg('SNMP error returned for message ID %s received from trunk %s: %s' % (msgId, trunkId, errorIndication))
        trunkRsp['error-indication'] = errorIndication

    trunkRsp['snmp-pdu'] = rspPDU
    
    log.msg('received SNMP %s message, sending trunk message #%s to trunk %s, original SNMP peer address %s:%s received at %s:%s, var-binds: %s' % (errorIndication and 'error' or 'response', msgId, trunkId, trunkReq['snmp-peer-address'], trunkReq['snmp-peer-port'], trunkReq['snmp-bind-address'], trunkReq['snmp-bind-port'], prettyVarBinds(rspPDU)))

    trunkingManager.sendRsp(trunkId, msgId, trunkRsp)

#
# The following needs proper support in pysnmp. Meanwhile - monkey patching!
#

q = []

origGetTargetAddr = lcd.getTargetAddr

def getTargetAddr(snmpEngine, snmpTargetAddrName):
    r = list(origGetTargetAddr(snmpEngine, snmpTargetAddrName))
    if q:
        r[1] = r[1].__class__(q[1]).setLocalAddress(q[0])
        q.pop(); q.pop()
    return r

lcd.getTargetAddr = getTargetAddr

def dataCbFun(trunkId, msgId, msg):
    k = [ str(x) for x in ( msg['snmp-engine-id'],
                            msg['snmp-transport-domain'],
                            msg['snmp-peer-address']+':'+str(msg['snmp-peer-port']),
                            msg['snmp-bind-address']+':'+str(msg['snmp-bind-port']),
                            msg['snmp-security-model'],
                            msg['snmp-security-level'],
                            msg['snmp-security-name'],
                            msg['snmp-context-engine-id'],
                            msg['snmp-context-name'] ) ]
    k.append(snmpPduTypesMap.get(msg['snmp-pdu'].tagSet, '?'))
    k.append('|'.join([str(x[0]) for x in v2c.apiPDU.getVarBinds(msg['snmp-pdu'])]))
    k = '#'.join(k) 
   
    for x,y in origCredIdList:
        if y.match(k):
            origPeerId = macro.expandMacros(x, msg)
            break
    else:
        origPeerId = None

    errorIndication = None

    peerIdList = routingMap.get((origPeerId, macro.expandMacros(trunkId, msg)))
    if not peerIdList:
        log.msg('unroutable trunk message #%s from trunk %s, orig-peer-id %s (original SNMP info: %s)' % (msgId, trunkId, origPeerId or '<none>', ', '.join([x == 'snmp-pdu' and 'snmp-var-binds=%s' % prettyVarBinds(msg['snmp-pdu']) or '%s=%s' % (x, msg[x].prettyPrint()) for x in msg])))
        errorIndication = 'no route to SNMP peer configured'

    cbCtx = trunkId, msgId, msg

    if errorIndication:
        __rspCbFun(None, None, errorIndication, None, cbCtx)
        return

    for peerId in peerIdList:
        peerId = macro.expandMacros(peerId, msg)

        snmpEngine, contextEngineId, contextName, \
            bindAddr, bindAddrMacro, \
            peerAddr, peerAddrMacro = peerIdMap[peerId]

        if bindAddrMacro:
            bindAddr = macro.expandMacros(bindAddrMacro, msg), 0
        if bindAddr:
            q.append(bindAddr)

        if peerAddrMacro:
            peerAddr = macro.expandMacros(peerAddrMacro, msg), 161
        if peerAddr:
            q.append(peerAddr)

        log.msg('received trunk message #%s from trunk %s, sending SNMP message to peer ID %s, bind-address %s, peer-address %s (original SNMP info: %s)' % (msgId, trunkId, peerId, bindAddr[0] or '<default>', peerAddr[0] or '<default>', ', '.join([x == 'snmp-pdu' and 'snmp-var-binds=%s' % prettyVarBinds(msg['snmp-pdu']) or '%s=%s' % (x, msg[x].prettyPrint()) for x in msg])))

        commandGenerator.sendPdu(
            snmpEngine,
            peerId,
            macro.expandMacros(contextEngineId, msg),
            macro.expandMacros(contextName, msg),
            msg['snmp-pdu'],
            __rspCbFun,
            cbCtx
        )

trunkingManager = TrunkingManager(dataCbFun)

def getTrunkAddr(a, port=0):
    f = lambda h,p=port: (h, int(p))
    try:
        return f(*a.split(':'))
    except:
        raise SnmpfwdError('improper IPv4 endpoint %s' % a)

for trunkCfgPath in cfgTree.getPathsToAttr('trunk-id'):
    trunkId = cfgTree.getAttrValue('trunk-id', *trunkCfgPath)
    secret = cfgTree.getAttrValue('trunk-crypto-key', *trunkCfgPath)
    secret = (secret*((16//len(secret))+1))[:16]
    log.msg('configuring trunk ID %s (at %s)...' % (trunkId, '.'.join(trunkCfgPath)))
    connectionMode = cfgTree.getAttrValue('trunk-connection-mode', *trunkCfgPath)
    if connectionMode == 'client':
        trunkingManager.addClient(
            trunkId,
            getTrunkAddr(cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath)),
            getTrunkAddr(cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath), 30201),
            secret
        )
        log.msg('new trunking client from %s to %s' % (cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath), cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath)))
    if connectionMode == 'server':
        trunkingManager.addServer(
            getTrunkAddr(cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath), 30201),
            secret
        )
        log.msg('new trunking server at %s' % (cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath)))

transportDispatcher.registerTimerCbFun(
    trunkingManager.monitorTrunks, random.randrange(1,5)
)

try:
    daemon.dropPrivileges(procUser, procGroup)
except:
    sys.stderr.write('ERROR: cant drop priveleges: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
    sys.exit(-1)

if not foregroundFlag:
    try:
        daemon.daemonize(pidFile)
    except:
        sys.stderr.write('ERROR: cant daemonize process: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
        sys.exit(-1)

# Run mainloop

log.msg('starting I/O engine...')

transportDispatcher.jobStarted(1) # server job would never finish

# Python 2.4 does not support the "finally" clause

exc_info = None

while True:
    try:
        transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        log.msg('shutting down process...')
        break
    except (PySnmpError, SnmpfwdError, socket.error):
        log.msg('error: %s' % sys.exc_info()[1])
        continue
    except Exception:
        exc_info = sys.exc_info()
        break

transportDispatcher.closeDispatcher()

log.msg('process terminated')

if exc_info:
    for line in traceback.format_exception(*exc_info):
        log.msg(line.replace('\n', ';'))
