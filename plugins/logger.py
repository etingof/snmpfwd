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
import stat
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
    'transport': 'udp',
    'facility': 'DAEMON',
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

        class TimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
            """Store log creation time in a stand-alone file''s mtime"""
            def __init__(self, *args, **kwargs):
                handlers.TimedRotatingFileHandler.__init__(self, *args, **kwargs)

                try:
                    timestamp = os.stat(self.__filename)[stat.ST_MTIME]

                except IOError:
                    return

                # Use a stand-aside file metadata time instead of the last
                # modification of the log file itself, as the stock
                # implementation does.
                # This is to work-around the increasing rotation intervals
                # on process restart.
                self.rolloverAt = self.computeRollover(timestamp)

            @property
            def __filename(self):
                return os.path.join(
                    os.path.dirname(self.baseFilename),
                    '.' + os.path.basename(self.baseFilename) + '-timestamp'
                )

            def doRollover(self):
                handlers.TimedRotatingFileHandler.doRollover(self)

                try:
                    # note log file creation time
                    open(self.__filename, 'w').close()

                except IOError:
                    pass


        filename = config.get('file', 'destination')

        handler = TimedRotatingFileHandler(
            filename,
            config.get('file', 'timescale'),
            int(config.get('file', 'interval')),
            int(config.get('file', 'backupcount'))
        )
        logger.addHandler(handler)

    else:
        raise SnmpfwdError('%s: unknown rotation method '
                           '%s at %s' % (PLUGIN_NAME, rotation, configFile))

elif method == 'syslog':

    try:
        transport = SYSLOG_TRANSPORTS[config.get('syslog', 'transport')]

    except KeyError:
        raise SnmpfwdError('%s: unknown syslog transport at %s' % (PLUGIN_NAME, configFile))

    facility = config.get('syslog', 'facility').lower()
    syslog_host = config.get('syslog', 'host')
    syslog_port = int(config.get('syslog', 'port'))

    handler = handlers.SysLogHandler(
        address=(syslog_host, syslog_port),
        facility=facility,
        socktype=transport)
    logger.addHandler(handler)

elif method == 'snmpfwd':

    class ProxyLogger(object):
        """Just a mock to convey logging calls to snmpfwd log"""
        error = log.error
        info = log.info
        debug = log.debug

        def __str__(self):
            return PLUGIN_NAME

        def setLevel(self, *args):
            return

    logger = ProxyLogger()

elif method == 'null':
    handler = logging.NullHandler()
    logger.addHandler(handler)

else:
    raise SnmpfwdError('%s: unknown logging method %s at %s' % (PLUGIN_NAME, method, configFile))

level = config.get('general', 'level').upper()

try:
    logger.setLevel(getattr(logging, level))

except AttributeError:
    raise SnmpfwdError('%s: unknown log level %s' % (PLUGIN_NAME, level))

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
