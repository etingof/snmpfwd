#!/usr/bin/env python
#
# SNMP Proxy Forwarder: SNMP client part
#
# Written by Ilya Etingof <ilya@snmplabs.com>, 2014
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
from pysnmp import debug
from snmpfwd import macro
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, daemon, cparser
from snmpfwd.trunking.manager import TrunkingManager

# Settings
programName = 'snmpfwd-client'
configVersion = '1'
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
    [--debug=<%s>]
    [--daemonize]
    [--process-user=<uname>] [--process-group=<gname>]
    [--pid-file=<file>]
    [--logging-method=<%s[:args>]>]
    [--config-file=<file>]""" % (
        sys.argv[0],
        '|'.join([ x for x in debug.flagMap.keys() if x != 'mibview' ]),
        '|'.join(log.gMap.keys())
    )

try:
    opts, params = getopt.getopt(sys.argv[1:], 'hv', [
        'help', 'version', 'debug=', 'daemonize', 'process-user=',
        'process-group=', 'pid-file=', 'logging-method=', 'config-file='
    ])
except Exception:
    sys.stderr.write('ERROR: %s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
    sys.exit(-1)

if params:
    sys.stderr.write('ERROR: extra arguments supplied %s\r\n%s\r\n' % (params, helpMessage))
    sys.exit(-1)

log.setLogger(programName, 'stderr')

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
    elif opt[0] == '--debug':
        debug.setLogger(debug.Debug(*opt[1].split(',')))
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
            log.setLogger(programName, *opt[1].split(':'))
        except SnmpfwdError:
            sys.stderr.write('%s\r\n%s\r\n' % (sys.exc_info()[1], helpMessage))
            sys.exit(-1)
    elif opt[0] == '--config-file':
        cfgFile = opt[1]

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

if cfgTree.getAttrValue('snmp-debug-categories', '', default=None):
    class PySnmpDebug(debug.Debug):
        defaultPrinter = log.msg
    
    debug.setLogger(PySnmpDebug(*cfgTree.getAttrValue('snmp-debug-categories', '').split(',')))

random.seed()

#
# SNMPv3 CommandGenerator implementation
#

gCurrentRequestContext = {}

commandGenerator = cmdgen.CommandGenerator()

origCredIdList = []
contentIdMap = {}
peerIdMap = {}
routingMap = {}
engineIdMap = {}

transportDispatcher = AsynsockDispatcher()
transportDispatcher.registerRoutingCbFun(lambda td,t,d: td)
transportDispatcher.setSocketMap()  # use global asyncore socket map

for peerEntryPath in cfgTree.getPathsToAttr('peer-id'):
    peerId = cfgTree.getAttrValue('peer-id', *peerEntryPath)
    log.msg('configuring peer %s (at %s)...' % (peerId, '.'.join(peerEntryPath)))

    engineId = cfgTree.getAttrValue('engine-id', *peerEntryPath)
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

    transportDomain = cfgTree.getAttrValue('transport-domain', *peerEntryPath)
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

        h, p = cfgTree.getAttrValue('bind-address', *peerEntryPath).split(':',1)
        snmpEngine.registerTransportDispatcher(
            transportDispatcher, transportDomain
        )
        config.addSocketTransport(
            snmpEngine,
            transportDomain,
            transport.openClientMode((h, int(p)))
        )

        snmpEngineMap['transportDomain'][transportDomain] = h, p, transportDomain
        log.msg('new transport endpoint at bind address %s:%s, transport ID %s' % (h, p, transportDomain))

    securityModel = cfgTree.getAttrValue('security-model', *peerEntryPath)
    securityModel = rfc1902.Integer(securityModel)
    securityLevel = cfgTree.getAttrValue('security-level', *peerEntryPath)
    securityLevel = rfc1902.Integer(securityLevel)
    securityName = cfgTree.getAttrValue('security-name', *peerEntryPath)

    contextEngineId = cfgTree.getAttrValue('context-engine-id', *peerEntryPath, default=None)
    contextName = cfgTree.getAttrValue('context-name', *peerEntryPath, default='')

    if securityModel in (1, 2):
        if securityName in snmpEngineMap['securityName']:
            if snmpEngineMap['securityName'][securityName] == securityModel:
                log.msg('using security-name %s' % securityName)
            else:
                raise error.SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
        else:
            communityName = cfgTree.getAttrValue('community-name', *peerEntryPath)
            config.addV1System(snmpEngine, securityName, communityName, 
                               securityName=securityName)

            log.msg('new community-name %s, security-name %s, security-level %s' % (communityName, securityName, securityLevel))
            snmpEngineMap['securityName'][securityName] = securityModel

    elif securityModel == 3:
        if securityName in snmpEngineMap['securityName']:
            if snmpEngineMap['securityName'][securityName] == securityModel:
                log.msg('using USM security-name: %s' % usmUser)
            else:
                raise error.SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
        else:
            usmUser = cfgTree.getAttrValue('usm-user', *peerEntryPath)
            log.msg('new USM user %s, security-model %s, security-level %s, security-name %s' % (usmUser, securityModel, securityLevel, securityName))

            if securityLevel in (2, 3):
                usmAuthProto = cfgTree.getAttrValue('usm-auth-proto', *peerEntryPath, default=config.usmHMACMD5AuthProtocol)
                usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                usmAuthKey = cfgTree.getAttrValue('usm-auth-key', *peerEntryPath)
                log.msg('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                if securityLevel == 3:
                    usmPrivProto = cfgTree.getAttrValue('usm-priv-proto', *peerEntryPath, default=config.usmDESPrivProtocol)
                    usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                    usmPrivKey = cfgTree.getAttrValue('usm-priv-key', *peerEntryPath, default=None)
                    log.msg('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))
            snmpEngineMap['securityName'][securityName] = securityModel

        config.addV3User(
            snmpEngine, usmUser,
            usmAuthProto, usmAuthKey,
            usmPrivProto, usmPrivKey
        )

    else:
        raise SnmpfwdError('unknown security-model: %s' % securityModel)

    credId = '/'.join([str(x) for x in securityName, securityLevel, securityModel])
    if credId in snmpEngineMap['credIds']:
        log.msg('using credentials ID %s...' % credId)
    else:
        config.addTargetParams(
            snmpEngine, credId, securityName, securityLevel, 
            securityModel == 3 and 3 or securityModel-1
        )
        log.msg('new credentials %s, security-name %s, security-level %s, security-model %s' % (credId, securityName, securityLevel, securityModel)) 
        snmpEngineMap['credIds'].add(credId)

    h, p = cfgTree.getAttrValue('transport-address', *peerEntryPath).split(':',1)
    config.addTargetAddr(
        snmpEngine, peerId, transportDomain, (h, int(p)), credId
    )

    peerIdMap[peerId] = snmpEngine, contextEngineId, contextName

    log.msg('new peer ID %s at target address %s:%s with credentials ID %s' % (peerId, h, p, credId))

for origCredCfgPath in cfgTree.getPathsToAttr('original-credentials-id'):
    origCredId = cfgTree.getAttrValue('original-credentials-id', *origCredCfgPath)
    k = '#'.join(
        ( cfgTree.getAttrValue('engine-id-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('transport-domain-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('transport-address-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('security-model-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('security-level-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('security-name-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('context-engine-id-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('context-name-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('pdu-type-pattern', *origCredCfgPath),
          cfgTree.getAttrValue('oid-prefix-pattern', *origCredCfgPath) )
    )

    log.msg('configuring original credentials ID %s (at %s), composite key: %r' % (origCredId, '.'.join(origCredCfgPath), k))

    origCredIdList.append((origCredId, re.compile(k)))

for routeCfgPath in cfgTree.getPathsToAttr('using-peer-id-list'):
    peerIdList = cfgTree.getAttrValue('using-peer-id-list', *routeCfgPath, vector=True)
    log.msg('configuring routing entry with peer IDs %s (at %s)...' % (','.join(peerIdList), '.'.join(routeCfgPath)))
    for credId in cfgTree.getAttrValue('matching-original-credentials-id-list', *routeCfgPath, vector=True):
        for trunkId in cfgTree.getAttrValue('matching-trunk-id-list', *routeCfgPath, vector=True):
            k = credId, trunkId
            if k in routingMap:
                log.msg('duplicate credentials-id %s and trunk-id %s at peer-id %s' % (credId, trunkId, ','.join(peerIdList)))
                sys.exit(-1)
            else:
                routingMap[k] = peerIdList

def __rspCbFun(snmpEngine, sendRequestHandle, errorIndication, rspPDU, cbCtx):
    trunkId, msgId, trunkReq = cbCtx
    
    trunkRsp = {}
        
    if errorIndication:
        log.msg('SNMP error returned for message ID %s received from trunk %s: %s' % (msgId, trunkId, errorIndication))
        trunkRsp['error-indication'] = errorIndication

    trunkRsp['pdu'] = rspPDU
    
    log.msg('received SNMP response message, sending trunk message #%s to trunk %s, original peer address %s' % (msgId, trunkId, trunkReq['transport-address']))

    trunkingManager.sendRsp(trunkId, msgId, trunkRsp)

def dataCbFun(trunkId, msgId, msg):
    k = [ str(x) for x in ( msg['engine-id'],
                            msg['transport-domain'],
                            msg['transport-address'],
                            msg['security-model'],
                            msg['security-level'],
                            msg['security-name'],
                            msg['context-engine-id'],
                            msg['context-name'] ) ]
    k.append(snmpPduTypesMap.get(msg['pdu'].tagSet, '?'))
    k.append('|'.join([str(x[0]) for x in v2c.apiPDU.getVarBinds(msg['pdu'])]))
    k = '#'.join(k) 
    
    for x,y in origCredIdList:
        if y.match(k):
            origCredentialsId = macro.expandMacros(x, msg)
            break
    else:
        origCredentialsId = None

    errorIndication = None

    peerIdList = routingMap.get((origCredentialsId, macro.expandMacros(trunkId, msg)))
    if not peerIdList:
        log.msg('unroutable message ID %s received from trunk %s (credentials ID %s)' % (msgId, trunkId, origCredentialsId))
        errorIndication = 'no route to SNMP peer configured'

    cbCtx = trunkId, msgId, msg

    if errorIndication:
        __rspCbFun(None, None, errorIndication, None, cbCtx)
        return

    for peerId in peerIdList:
        peerId = macro.expandMacros(peerId, msg)
        log.msg('received trunk message #%s from trunk %s, sending SNMP message to peer ID %s (chosen by original credentials ID %s), peer address %s' % (msgId, trunkId, peerId, origCredentialsId, msg['transport-address']))

        snmpEngine, contextEngineId, contextName = peerIdMap[peerId]

        commandGenerator.sendPdu(
            snmpEngine,
            peerId,
            macro.expandMacros(contextEngineId, msg),
            macro.expandMacros(contextName, msg),
            msg['pdu'],
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
    secret = cfgTree.getAttrValue('secret', *trunkCfgPath)
    secret = (secret*((16/len(secret))+1))[:16]
    log.msg('configuring trunk ID %s (at %s)...' % (trunkId, '.'.join(trunkCfgPath)))
    connectionMode = cfgTree.getAttrValue('connection-mode', *trunkCfgPath)
    if connectionMode == 'client':
        trunkingManager.addClient(
            trunkId,
            getTrunkAddr(cfgTree.getAttrValue('local-address', *trunkCfgPath)),
            getTrunkAddr(cfgTree.getAttrValue('remote-address', *trunkCfgPath), 30201),
            secret
        )
        log.msg('new trunking client from %s to %s' % (cfgTree.getAttrValue('local-address', *trunkCfgPath), cfgTree.getAttrValue('remote-address', *trunkCfgPath)))
    if connectionMode == 'server':
        trunkingManager.addServer(
            getTrunkAddr(cfgTree.getAttrValue('local-address', *trunkCfgPath), 30201),
            secret
        )
        log.msg('new trunking server at %s' % (cfgTree.getAttrValue('local-address', *trunkCfgPath)))

transportDispatcher.registerTimerCbFun(
    trunkingManager.monitorTrunks, random.randrange(1,5)
)

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
