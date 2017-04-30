#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2017, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/etingof/snmpfwd/blob/master/LICENSE.txt
#
# SNMP Proxy Forwarder plugin module
#
import logging
from logging import handlers
try:
    from ConfigParser import RawConfigParser, Error
except ImportError:
    from configparser import RawConfigParser, Error
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import msg
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'
apiVersions = 0, 2

# defaults
pduMap = {}
method = 'null'
logFormat = ''
leftParen, rightParen = '', ''

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
            raise SnmpfwdError('logger: unknown rotation method: %s' % rotation)
    else:
        raise SnmpfwdError('logger: unknown logging method: %s' % method)

    msg('logger: using %s logging method' % method)

    logger.setLevel(logging.INFO)

    pdus = config.get('content', 'pdus')
    for pdu in pdus.split():
        try:
            pduMap[getattr(v2c, pdu + 'PDU').tagSet] = pdu
        except AttributeError:
            raise SnmpfwdError('logger: unknown PDU %s' % pdu)
        else:
            msg('logger: PDU ACL includes %s' % pdu)
        
    handler.setFormatter(
        logging.Formatter(config.get('content', 'format').replace('-', '_'))
    )

    try:
        leftParen, rightParen = config.get('content', 'parentheses').split()

    except Error:
        pass

    msg('logger: using var-bind value parentheses "%s" "%s"' % (leftParen, rightParen))

    logger.addHandler(handler)

msg('logger: plugin initialization complete')


def _makeExtra(pdu, context):
    extra = dict([(x[0].replace('-', '_'), x[1]) for x in context.items()])
    extra['snmp_var_binds'] = ' '.join(['%s %s%s%s' % (vb[0].prettyPrint(), leftParen, vb[1].prettyPrint(), rightParen) for vb in v2c.apiPDU.getVarBinds(pdu)])
    extra['snmp_pdu_type'] = pduMap[pdu.tagSet]
    return extra


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet in pduMap:
        logger.info('', extra=_makeExtra(pdu, snmpReqInfo))
    return status.NEXT, pdu


def processCommandResponse(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet in pduMap:
        logger.info('', extra=_makeExtra(pdu, snmpReqInfo))
    return status.NEXT, pdu
