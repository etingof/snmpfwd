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
import os
import socket
try:
    from ConfigParser import RawConfigParser, Error
except ImportError:
    from configparser import RawConfigParser, Error
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd import log
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'

apiVersions = 0, 2

PLUGIN_NAME = 'logger'

DEFAULTS = {
    # general
    'method': 'snmpfwd',
    'level': 'INFO',

    # file
    'rotation': 'timed',
    'backupcount': 30,
    'timescale': 'D',
    'interval': 1,

    # syslog
    'transport': 'socket',
    'facility': 'daemon',
    'host': 'localhost',
    'port': 514,

    # content
    'pdus': ('GetRequest GetNextRequest SetRequest '
             'GetBulkRequest InformRequest SNMPv2Trap Response'),
    'template': '${isotime} ${callflow-id} ${snmp-peer-address} '
                '${snmp-pdu-type} ${snmp-var-binds}',
    'parentheses': '" "'
}

SYSLOG_TRANSPORTS = {
    'udp': socket.SOCK_DGRAM,
    'tcp': socket.SOCK_STREAM
}

SYSLOG_SOCKET_PATHS = (
    '/dev/log',
    '/var/run/syslog'
)

PDU_MAP = {}

# NOTE(etingof): this is a root logger
logger = logging.getLogger('snmpfwd-logger')

config = RawConfigParser(defaults=DEFAULTS)

for moduleOption in moduleOptions:

    optionName, optionValue = moduleOption.split('=', 1)

    if optionName == 'config':

        configFile = optionValue

        config.read(configFile)

method = config.get('general', 'method')
if method == 'file':

    rotation = config.get('file', 'rotation')

    if rotation == 'timed':

        filename = config.get('file', 'destination')

        handler = log.FileLogger.TimedRotatingFileHandler(
            filename,
            config.get('file', 'timescale'),
            int(config.get('file', 'interval')),
            int(config.get('file', 'backupcount'))
        )

    else:
        raise SnmpfwdError('%s: unknown rotation method %s' % (PLUGIN_NAME, rotation))

elif method == 'syslog':

    transport = config.get('syslog', 'transport')

    if transport in SYSLOG_TRANSPORTS:
        address = (
            config.get('syslog', 'host'),
            int(config.get('syslog', 'port'))
        )

    else:
        address = None

        for dev in SYSLOG_SOCKET_PATHS:
            if os.path.exists(dev):
                address = dev
                transport = None
                break

        if transport and transport.startswith(os.path.sep):
            address = transport
            transport = None

        if not address:
            raise SnmpfwdError('Unknown syslog transport configured')

    facility = config.get('syslog', 'facility').lower()

    handler = handlers.SysLogHandler(
        address=address,
        facility=facility,
        socktype=transport)

elif method == 'snmpfwd':

    class ProxyLogger(object):
        """Just a mock to convey logging calls to snmpfwd log"""
        error = log.error
        info = log.info
        debug = log.debug

        def __str__(self):
            return PLUGIN_NAME

    handler = None
    logger = ProxyLogger()

elif method == 'null':
    handler = logging.NullHandler()

else:
    raise SnmpfwdError('%s: unknown logging method %s' % (PLUGIN_NAME, method))

if handler:
    level = config.get('general', 'level').upper()

    try:
        level = getattr(logging, level)

    except AttributeError:
        raise SnmpfwdError('%s: unknown log level %s' % (PLUGIN_NAME, level))

    handler.setLevel(level)

    # set logger level if this is a root logger (i.e. separate from snmpfwd)
    logger.setLevel(level)

    logger.addHandler(handler)

template = config.get('content', 'template')

logger.debug('%s: using %s logging method' % (PLUGIN_NAME, method))

pdus = config.get('content', 'pdus')
for pdu in pdus.split():
    try:
        PDU_MAP[getattr(v2c, pdu + 'PDU').tagSet] = pdu

    except AttributeError:
        raise SnmpfwdError('%s: unknown PDU %s' % (PLUGIN_NAME, pdu))

    else:
        logger.debug('%s: PDU ACL includes %s' % (PLUGIN_NAME, pdu))

try:
    leftParen, rightParen = config.get('content', 'parentheses').split()

except Exception:
    raise SnmpfwdError('%s: malformed "parentheses" values' % PLUGIN_NAME)

logger.debug('%s: using var-bind value parentheses %s %s' % (PLUGIN_NAME, leftParen, rightParen))

started = time.time()

logger.info('%s: plugin initialization complete' % PLUGIN_NAME)


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
        template = template.replace(token, PDU_MAP[pdu.tagSet])

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
    if pdu.tagSet in PDU_MAP:
        logger.info(_format(template, pdu, trunkMsg))

    return status.NEXT, pdu


processCommandResponse = processCommandRequest

processNotificationRequest = processCommandRequest

processNotificationResponse = processCommandRequest
