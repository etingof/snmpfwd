#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
# SNMP Proxy Forwarder plugin module
#
import logging
from logging import handlers
import time
try:
    from ConfigParser import RawConfigParser, Error
except ImportError:
    from configparser import RawConfigParser, Error
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import debug, info, error
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

for moduleOption in moduleOptions:

    optionName, optionValue = moduleOption.split('=', 1)

    if optionName == 'config':

        configFile = optionValue

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

        debug('%s: using %s logging method' % (PLUGIN_NAME, method))

        logger.setLevel(logging.INFO)

        pdus = config.get('content', 'pdus')
        for pdu in pdus.split():
            try:
                pduMap[getattr(v2c, pdu + 'PDU').tagSet] = pdu

            except AttributeError:
                raise SnmpfwdError('%s: unknown PDU %s' % (PLUGIN_NAME, pdu))

            else:
                debug('%s: PDU ACL includes %s' % (PLUGIN_NAME, pdu))

        try:
            leftParen, rightParen = config.get('content', 'parentheses').split()

        except Exception:
            error('%s: malformed "parentheses" values at %s' % (PLUGIN_NAME, configFile))

        template = config.get('content', 'template')

        debug('%s: using var-bind value parentheses %s %s' % (PLUGIN_NAME, leftParen, rightParen))

        logger.addHandler(handler)

started = time.time()

info('%s: plugin initialization complete' % PLUGIN_NAME)


def _format(template, pdu, context):
    for key, value in context.items():
        token = '${%s}' % key
        if token in template:
            template = template.replace(token, str(value))

    token = '${snmp-var-binds}'
    if token in template:
        varBinds = ['%s %s%s%s' % (vb[0].prettyPrint(),
                                   leftParen,
                                   vb[1].prettyPrint().replace(leftParen, leftParen + leftParen).replace(rightParen, rightParen + rightParen),
                                   rightParen)
                    for vb in v2c.apiPDU.getVarBinds(pdu)]
        template = template.replace(token, ' '.join(varBinds))

    token = '${snmp-pdu-type}'
    if token in template:
        template = template.replace(token, pduMap[pdu.tagSet])

    now = time.time()

    token = '${asctime}'
    if token in template:
        timestamp = time.asctime(time.localtime(now))
        template = template.replace(token, timestamp)

    token = '${isotime}'
    if token in template:
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now))
        timestamp += '.%02d' % (now % 1 * 100)
        template = template.replace(token, timestamp)

    token = '${timestamp}'
    if token in template:
        timestamp = '%.2f' % now
        template = template.replace(token, timestamp)

    token = '${uptime}'
    if token in template:
        timestamp = '%012.2f' % (time.time() - started)
        template = template.replace(token, timestamp)

    return template


def processCommandRequest(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):
    if pdu.tagSet in pduMap:
        logger.info(_format(template, pdu, trunkMsg))

    return status.NEXT, pdu

processCommandResponse = processCommandRequest

processNotificationRequest = processCommandRequest

processNotificationResponse = processCommandRequest
