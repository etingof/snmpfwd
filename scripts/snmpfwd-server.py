#!/usr/bin/env python
#
# SNMP Proxy Forwarder: server part
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
from pysnmp.entity.rfc3413 import cmdrsp, context
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
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, daemon, cparser, macro
from snmpfwd.trunking.manager import TrunkingManager

# Settings
programName = 'snmpfwd-server'
configVersion = '1'
pidFile = ''
cfgFile = '/usr/local/etc/snmpfwd/server.cfg'
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
  SNMP Proxy Forwarder: server part. Receives SNMP requests at one or many
  built-in SNMP Agents and routes them to encrypted trunks established with
  Forwarder's Manager part(s) running elsewhere.
  Can implement complex routing logic through analyzing parts of SNMP messages
  and matching them against proxying rules.
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

random.seed()

if cfgTree.getAttrValue('snmp-debug-categories', '', default=None):
    class PySnmpDebug(debug.Debug):
        defaultPrinter = log.msg
    
    debug.setLogger(PySnmpDebug(*cfgTree.getAttrValue('snmp-debug-categories', '').split(',')))

#
# SNMPv3 CommandResponder implementation
#

gCurrentRequestContext = {}

class CommandResponder(cmdrsp.CommandResponderBase):
    pduTypes = ( rfc1905.SetRequestPDU.tagSet,
                 rfc1905.GetRequestPDU.tagSet,
                 rfc1905.GetNextRequestPDU.tagSet,
                 rfc1905.GetBulkRequestPDU.tagSet )
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName,
                            PDU, acInfo):
        trunkIdList = gCurrentRequestContext['trunk-id-list']
        if trunkIdList is None:
            log.msg('no route configured for request %s: %r' %
                    (stateReference, gCurrentRequestContext))
            self.releaseStateInformation(stateReference)
            return

        trunkReq = gCurrentRequestContext['request']
        trunkReq['pdu'] = PDU

        for trunkId in trunkIdList:
            log.msg('received SNMP message from peer address %s, sending through trunk %s' % (trunkReq['transport-address'], trunkId))

            cbCtx = trunkId, trunkReq, snmpEngine, stateReference

            trunkingManager.sendReq(trunkId, trunkReq, self.__recvCb, cbCtx)

    def __recvCb(self, trunkRsp, cbCtx):
        trunkId, trunkReq, snmpEngine, stateReference = cbCtx

        if trunkRsp['error-indication']:
            log.msg('received trunk message through trunk %s, remote end reported error-indication %s, NOT sending response to peer address %s' % (trunkId, trunkRsp['error-indication'], trunkReq['transport-address']))
        else:
            log.msg('received trunk message through trunk %s, sending SNMP response to peer address %s' % (trunkId, trunkReq['transport-address'],))

            self.sendPdu(
                snmpEngine,
                stateReference,
                trunkRsp['pdu']
            )

        self.releaseStateInformation(stateReference)

credIdMap = {}
peerIdMap = {}
contextIdList = []
contentIdList = []
contentIdMap = {}
trunkIdMap = {}
engineIdMap = {}

transportDispatcher = AsynsockDispatcher()
transportDispatcher.registerRoutingCbFun(lambda td,t,d: td)
transportDispatcher.setSocketMap()  # use global asyncore socket map

snmpPduTypesMap = {
    rfc1905.GetRequestPDU.tagSet: 'GET',
    rfc1905.SetRequestPDU.tagSet: 'SET',
    rfc1905.GetNextRequestPDU.tagSet: 'GETNEXT',
    rfc1905.GetBulkRequestPDU.tagSet: 'GETBULK',
    rfc1905.ResponsePDU.tagSet: 'RESPONSE'
}

def requestObserver(snmpEngine, execpoint, variables, cbCtx):
    cbCtx['credentials-id'] = macro.expandMacros(
        credIdMap.get(
            ( snmpEngine.snmpEngineID,
              variables['transportDomain'],
              variables['securityModel'],
              variables['securityLevel'],
              variables['securityName'] )
        ),
        variables
    )

    k = '#'.join([str(x) for x in (variables['contextEngineId'], variables['contextName'])])
    for x,y in contextIdList:
        if y.match(k):
            cbCtx['context-id'] = macro.expandMacros(x, variables)
            break
        else:
            cbCtx['context-id'] = None

    transportAddress = str(variables['transportAddress'][0])
    for pat, peerId in peerIdMap.get(str(variables['transportDomain']), ()):
        if pat.match(transportAddress):
            cbCtx['peer-id'] = macro.expandMacros(peerId, variables)
            break
    else:
        cbCtx['peer-id'] = None

    k = '#'.join(
        [ snmpPduTypesMap.get(variables['pdu'].tagSet, '?'),
        '|'.join([str(x[0]) for x in v2c.apiPDU.getVarBinds(variables['pdu'])]) ] 
    )

    for x,y in contentIdList:
        if y.match(k):
            cbCtx['content-id'] = macro.expandMacros(x, variables)
            break
        else:
            cbCtx['content-id'] = None

    cbCtx['trunk-id-list'] = trunkIdMap.get(
        ( cbCtx['credentials-id'],
          cbCtx['context-id'],
          cbCtx['peer-id'],
          cbCtx['content-id'] )
    )
    cbCtx['request'] = {
        'engine-id': snmpEngine.snmpEngineID,
        'transport-domain': variables['transportDomain'],
        'transport-address': variables['transportAddress'][0], # XXX
        'security-model': variables['securityModel'],
        'security-level': variables['securityLevel'],
        'security-name': variables['securityName'],
        'context-engine-id': variables['contextEngineId'],
        'context-name': variables['contextName']
    }

for configEntryPath in cfgTree.getPathsToAttr('credentials-id'):
    credId = cfgTree.getAttrValue('credentials-id', *configEntryPath)
    configKey = []
    log.msg('configuring credentials %s (at %s)...' % (credId, '.'.join(configEntryPath)))

    engineId = cfgTree.getAttrValue('engine-id', *configEntryPath)
    
    if engineId in engineIdMap:
        snmpEngine, snmpContext, snmpEngineMap = engineIdMap[engineId]
        log.msg('using engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())
    else:
        snmpEngine = engine.SnmpEngine(snmpEngineID=engineId)
        snmpContext = context.SnmpContext(snmpEngine)
        snmpEngineMap = {
            'transportDomain': {},
            'securityName': {}
        }

        snmpEngine.observer.registerObserver(
            requestObserver,
            'rfc3412.receiveMessage:request',
            cbCtx=gCurrentRequestContext
        )

        CommandResponder(snmpEngine, snmpContext)

        engineIdMap[engineId] = snmpEngine, snmpContext, snmpEngineMap

        log.msg('new engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())

    configKey.append(str(snmpEngine.snmpEngineID))

    transportDomain = cfgTree.getAttrValue('transport-domain', *configEntryPath)
    transportDomain = rfc1902.ObjectName(transportDomain)

    if transportDomain in snmpEngineMap['transportDomain']:
        h, p, transportDomain = snmpEngineMap['transportDomain'][transportDomain]
        log.msg('using transport endpoint %s:%s, transport ID %s' % (h, p, transportDomain))
    else:
        if transportDomain[:len(udp.domainName)] == udp.domainName:
            transport = udp.UdpTransport()
        elif transportDomain[:len(udp6.domainName)] == udp6.domainName:
            transport = udp6.Udp6Transport()
        else:
            log.msg('unknown transport domain %s' % (transportDomain,))
            sys.exit(-1)

        h, p = cfgTree.getAttrValue('transport-address', *configEntryPath).split(':',1)

        snmpEngine.registerTransportDispatcher(
            transportDispatcher, transportDomain
        )
        config.addSocketTransport(
            snmpEngine,
            transportDomain,
            transport.openServerMode((h, int(p)))
        )

        snmpEngineMap['transportDomain'][transportDomain] = h, p, transportDomain
        log.msg('new transport endpoint %s:%s, transport ID %s' % (h, p, transportDomain))

    configKey.append(transportDomain)

    securityModel = cfgTree.getAttrValue('security-model', *configEntryPath)
    securityModel = rfc1902.Integer(securityModel)
    securityLevel = cfgTree.getAttrValue('security-level', *configEntryPath)
    securityLevel = rfc1902.Integer(securityLevel)
    securityName = cfgTree.getAttrValue('security-name', *configEntryPath)

    if securityModel in (1, 2):
        if securityName in snmpEngineMap['securityName']:
            if snmpEngineMap['securityName'][securityModel] == securityModel:
                log.msg('using security-name %s' % securityName)
            else:
                raise error.SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
        else:
            communityName = cfgTree.getAttrValue('community-name', *configEntryPath)
            config.addV1System(snmpEngine, securityName, communityName, 
                               securityName=securityName)
            log.msg('new community-name %s, security-name %s, security-level %s' % (communityName, securityName, securityLevel))
            snmpEngineMap['securityName'][securityName] = securityModel

        configKey.append(securityModel)
        configKey.append(securityLevel)
        configKey.append(securityName)

    elif securityModel == 3:
        if securityName in snmpEngineMap['securityName']:
            log.msg('using USM security-name: %s' % securityName)
        else:
            usmUser = cfgTree.getAttrValue('usm-user', *configEntryPath)
            log.msg('new USM user %s, security-model %s, security-level %s, security-name %s' % (usmUser, securityModel, securityLevel, securityName))

            if securityLevel in (2, 3):
                usmAuthProto = cfgTree.getAttrValue('usm-auth-proto', *configEntryPath, default=config.usmHMACMD5AuthProtocol)
                usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                usmAuthKey = cfgTree.getAttrValue('usm-auth-key', *configEntryPath)
                log.msg('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                if securityLevel == 3:
                    usmPrivProto = cfgTree.getAttrValue('usm-priv-proto', *configEntryPath, default=config.usmDESPrivProtocol)
                    usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                    usmPrivKey = cfgTree.getAttrValue('usm-priv-key', *configEntryPath, default=None)
                    log.msg('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))

            snmpEngineMap['securityName'][securityName] = securityModel

        config.addV3User(
            snmpEngine, usmUser,
            usmAuthProto, usmAuthKey,
            usmPrivProto, usmPrivKey
        )

        configKey.append(securityModel)
        configKey.append(securityLevel)
        configKey.append(securityName)

    else:
        raise SnmpfwdError('unknown security-model: %s' % securityModel)

    credIdMap[tuple(configKey)] = credId

for peerCfgPath in cfgTree.getPathsToAttr('peer-id'):
    peerId = cfgTree.getAttrValue('peer-id', *peerCfgPath)
    log.msg('configuring peer ID %s (at %s)...' % (peerId, '.'.join(peerCfgPath)))
    transportDomain = cfgTree.getAttrValue('transport-domain', *peerCfgPath)
    if transportDomain not in peerIdMap:
        peerIdMap[transportDomain] = []
    for transportAddress in cfgTree.getAttrValue('transport-address-pattern-list', *peerCfgPath, vector=True):
        peerIdMap[transportDomain].append(
            (re.compile(transportAddress), peerId)
        )

for contextCfgPath in cfgTree.getPathsToAttr('context-id'):
    contextId = cfgTree.getAttrValue('context-id', *contextCfgPath)
    k = '#'.join(
        ( cfgTree.getAttrValue('context-engine-id-pattern', *contextCfgPath),
          cfgTree.getAttrValue('context-name-pattern', *contextCfgPath) )
    )
    
    log.msg('configuring context ID %s (at %s), composite key: %r' % (contextId, '.'.join(contextCfgPath), k))

    contextIdList.append((contextId, re.compile(k)))
    
for contentCfgPath in cfgTree.getPathsToAttr('content-id'):
    contentId = cfgTree.getAttrValue('content-id', *contentCfgPath)
    for x in cfgTree.getAttrValue('oid-prefix-pattern-list', *contentCfgPath, vector=True):
        k = '#'.join([ cfgTree.getAttrValue('pdu-type-pattern', *contentCfgPath), x ])

        log.msg('configuring content ID %s (at %s), composite key: %r' % (contentId, '.'.join(contentCfgPath), k))

        contentIdList.append((contentId, re.compile(k)))

for routeCfgPath in cfgTree.getPathsToAttr('using-trunk-id-list'):
    trunkIdList = cfgTree.getAttrValue('using-trunk-id-list', *routeCfgPath, vector=True)
    log.msg('configuring destination trunk ID(s) %s (at %s)...' % (','.join(trunkIdList), '.'.join(routeCfgPath)))
    for credId in cfgTree.getAttrValue('matching-credentials-id-list', *routeCfgPath, vector=True):
        for peerId in cfgTree.getAttrValue('matching-peer-id-list', *routeCfgPath, vector=True):
            for contextId in cfgTree.getAttrValue('matching-context-id-list', *routeCfgPath, vector=True):
                for contentId in cfgTree.getAttrValue('matching-content-id-list', *routeCfgPath, vector=True):
                    k = credId, contextId, peerId, contentId
                    if k in trunkIdMap:
                        log.msg('duplicate credentials-id %s, context-id %s, peer-id %s, content-id %s at trunk-id(s) %s' % (credId, contextId, peerId, contentId, ','.join(trunkId)))
                        sys.exit(-1)
                    else:
                        trunkIdMap[k] = trunkIdList

def dataCbFun(trunkId, msgId, msg):
    log.msg('message ID %s received from trunk %s' % (msgId, trunkId))

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
