# SNMP Forwarder plugin module
import logging
from logging import handlers
try:
    from ConfigParser import RawConfigParser, Error
except ImportError:
    from configparser import RawConfigParser, Error
from snmpfwd.plugins import status
from snmpfwd.log import msg
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'
apiVersions = 0, 1

# defaults
pduMap = {}
method = 'null'
format = ''
parentheses = ('', '')

logger = logging.getLogger('snmpfwd-logger')

moduleOptions = moduleOptions.split('=')
if moduleOptions[0] == 'config':
    config = RawConfigParser()
    config.read(moduleOptions[1])

    method = config.get('general', 'method')
    if method == 'file':
        rotation = config.get('file', 'rotation')
        if rotation == 'timed':
            handler = handlers.TimedRotatingFileHandler(
                config.get('file', 'destination'),
                config.get('file', 'timescale'),
                int(config.get('file', 'interval')),
                int(config.get('file', 'backupcount'))
             )
        else:
            raise SnmpfwdError('logger: unknown rotation method' % rotation)
    else:
        raise SnmpfwdError('logger: unknown logging method' % method)

    msg('logger: using %s logging method' % method)

    logger.setLevel(logging.INFO)

    pdus = config.get('content', 'pdus')
    for pdu in pdus.split():
        try:
            pduMap[getattr(v2c, pdu+'PDU').tagSet] = pdu
        except AttributeError:
            raise SnmpfwdError('logger: unknown PDU %s' % pdu)
        else:
            msg('logger: PDU ACL includes %s' % pdu)
        
    handler.setFormatter(
        logging.Formatter(config.get('content', 'format').replace('-', '_'))
    )

    try:
        parentheses = tuple(config.get('content', 'parentheses').split())
    except Error:
        pass

    msg('logger: using var-bind value parentheses "%s" "%s"' % parentheses)

    logger.addHandler(handler)

msg('logger: plugin initialization complete')

def _makeExtra(pdu, context):
    extra = dict([(x[0].replace('-', '_'),x[1]) for x in context.items()])
    extra['snmp_var_binds'] = ' '.join([ '%s %s%s%s' % (vb[0].prettyPrint(), parentheses[0], vb[1].prettyPrint(), parentheses[1]) for vb in v2c.apiPDU.getVarBinds(pdu) ])
    extra['snmp_pdu_type'] = pduMap[pdu.tagSet]
    return extra

def processCommandRequest(pluginId, snmpEngine, pdu, **context):
    if pdu.tagSet in pduMap:
        logger.info('', extra=_makeExtra(pdu, context))
    return status.NEXT, pdu

def processCommandResponse(pluginId, snmpEngine, pdu, **context):
    if pdu.tagSet in pduMap:
        logger.info('', extra=_makeExtra(pdu, context))
    return status.NEXT, pdu

