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

PLUGIN_NAME = 'logger'

# defaults
pduMap = {}
method = 'null'
logFormat = ''
leftParen, rightParen = '', ''

logger = logging.getLogger('snmpfwd-logger')

moduleOptions = moduleOptions.split('=')

if moduleOptions[0] == 'config':
    configFile = moduleOptions[1]

    config = RawConfigParser()
    config.read(configFile)

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
            raise SnmpfwdError('%s: unknown rotation method %s at %s' % (PLUGIN_NAME, rotation, configFile))
    else:
        raise SnmpfwdError('%s: unknown logging method %s at %s' % (PLUGIN_NAME, method, configFile))

    msg('%s: using %s logging method' % (PLUGIN_NAME, method))

    logger.setLevel(logging.INFO)

    pdus = config.get('content', 'pdus')
    for pdu in pdus.split():
        try:
            pduMap[getattr(v2c, pdu + 'PDU').tagSet] = pdu

        except AttributeError:
            raise SnmpfwdError('%s: unknown PDU %s' % (PLUGIN_NAME, pdu))

        else:
            msg('%s: PDU ACL includes %s' % (PLUGIN_NAME, pdu))

    try:
        leftParen, rightParen = config.get('content', 'parentheses').split()

    except Exception:
        msg('%s: malformed "parentheses" values at %s' % (PLUGIN_NAME, configFile))

    msg('%s: using var-bind value parentheses "%s" "%s"' % (PLUGIN_NAME, leftParen, rightParen))

    logger.addHandler(handler)

msg('%s: plugin initialization complete' % PLUGIN_NAME)


def _format(pdu, context):
    extra = dict([(x[0].replace('-', '_'), x[1]) for x in context.items()])

    extra['snmp_var_binds'] = ' '.join(
        ['%s %s%s%s' % (vb[0].prettyPrint(),
                        leftParen,
                        vb[1].prettyPrint().replace(leftParen, leftParen + leftParen).replace(rightParen, rightParen + rightParen), rightParen)
         for vb in v2c.apiPDU.getVarBinds(pdu)]
    )

    extra['snmp_pdu_type'] = pduMap[pdu.tagSet]

    return extra


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet in pduMap:
        logger.info('', extra=_format(pdu, snmpReqInfo))

    return status.NEXT, pdu


def processCommandResponse(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    if pdu.tagSet in pduMap:
        logger.info('', extra=_format(pdu, snmpReqInfo))

    return status.NEXT, pdu
