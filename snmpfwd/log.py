#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import os
import sys
import logging
import socket
import stat
import time
from logging import handlers
from snmpfwd.error import SnmpfwdError

LOG_DEBUG = 0
LOG_INFO = 1
LOG_ERROR = 2


class AbstractLogger(object):
    def __init__(self, progId, *priv):
        self._logger = logging.getLogger(progId)
        self._logger.setLevel(logging.DEBUG)
        self._progId = progId
        self.init(*priv)

    def __call__(self, s):
        self._logger.debug(s)

    def init(self, *priv):
        pass


class SyslogLogger(AbstractLogger):
    SYSLOG_SOCKET_PATHS = (
        '/dev/log',
        '/var/run/syslog'
    )

    def init(self, *priv):
        if len(priv) < 1:
            raise SnmpfwdError('Bad syslog params, need at least facility, also accept '
                               'host, port, socktype (tcp|udp)')
        if len(priv) < 2:
            priv = [priv[0], 'debug']
        if len(priv) < 3:
            # search for syslog local socket

            for dev in self.SYSLOG_SOCKET_PATHS:
                if os.path.exists(dev):
                    priv = [priv[0], priv[1], dev]
                    break
            else:
                priv = [priv[0], priv[1], 'localhost', 514, 'udp']

        if not priv[2].startswith('/'):
            if len(priv) < 4:
                priv = [priv[0], priv[1], priv[2], 514, 'udp']
            if len(priv) < 5:
                priv = [priv[0], priv[1], priv[2], 514, 'udp']
            priv = [priv[0], priv[1], priv[2], int(priv[3]), priv[4]]

        try:
            handler = handlers.SysLogHandler(
                address=priv[2].startswith('/') and priv[2] or (priv[2], int(priv[3])),
                facility=priv[0].lower(),
                socktype=len(priv) > 4 and priv[4] == 'tcp' and socket.SOCK_STREAM or socket.SOCK_DGRAM
            )

        except Exception:
            raise SnmpfwdError('Bad syslog option(s): %s' % sys.exc_info()[1])

        handler.setFormatter(logging.Formatter('%(asctime)s %(name)s: %(message)s'))

        self._logger.addHandler(handler)


class FileLogger(AbstractLogger):

    class TimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
        """Store log creation time in a stand-alone file''s mtime"""

        def __init__(self, *args, **kwargs):
            handlers.TimedRotatingFileHandler.__init__(self, *args, **kwargs)

            self.__failure = False

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
            try:
                handlers.TimedRotatingFileHandler.doRollover(self)

                # note log file creation time
                if os.path.exists(self.__filename):
                    os.unlink(self.__filename)

                open(self.__filename, 'w').close()

                self.__failure = False

            except IOError:
                # File rotation seems to fail, postpone the next run
                timestamp = time.time()
                self.rolloverAt = self.computeRollover(timestamp)

                if not self.__failure:
                    self.__failure = True
                    error('Failed to rotate log/timestamp file '
                          '%s: %s' % (self.__filename, sys.exc_info()[1]))

    def init(self, *priv):
        if not priv:
            raise SnmpfwdError('Bad log file params, need filename')
        if sys.platform[:3] == 'win':
            # fix possibly corrupted absolute windows path
            if len(priv[0]) == 1 and priv[0].isalpha() and len(priv) > 1:
                priv = [priv[0] + ':' + priv[1]] + list(priv[2:])

        maxsize = 0
        maxage = None
        if len(priv) > 1 and priv[1]:
            try:
                if priv[1][-1] == 'k':
                    maxsize = int(priv[1][:-1]) * 1024
                elif priv[1][-1] == 'm':
                    maxsize = int(priv[1][:-1]) * 1024 * 1024
                elif priv[1][-1] == 'g':
                    maxsize = int(priv[1][:-1]) * 1024 * 1024 * 1024
                elif priv[1][-1] == 'S':
                    maxage = ('S', int(priv[1][:-1]))
                elif priv[1][-1] == 'M':
                    maxage = ('M', int(priv[1][:-1]))
                elif priv[1][-1] == 'H':
                    maxage = ('H', int(priv[1][:-1]))
                elif priv[1][-1] == 'D':
                    maxage = ('D', int(priv[1][:-1]))
                else:
                    raise ValueError('Unknown log rotation criterion: %s' % priv[1][-1])

            except ValueError:
                raise SnmpfwdError(
                    'Error in timed log rotation specification. Use <NNN>k,m,g '
                    'for size or <NNN>S,M,H,D for time limits'
                )

        try:
            if maxsize:
                handler = handlers.RotatingFileHandler(priv[0], backupCount=30, maxBytes=maxsize)
            elif maxage:
                handler = self.TimedRotatingFileHandler(priv[0], backupCount=30, when=maxage[0], interval=maxage[1])
            else:
                handler = handlers.WatchedFileHandler(priv[0])

        except Exception:
            raise SnmpfwdError(
                'Failure configure logging: %s' % sys.exc_info()[1]
            )

        handler.setFormatter(logging.Formatter('%(message)s'))

        self._logger.addHandler(handler)

        self('Log file %s, rotation rules: %s' % (priv[0], maxsize and '> %sKB' % (maxsize/1024) or maxage and '%s%s' % (maxage[1], maxage[0]) or '<none>'))

    def __call__(self, s):
        now = time.time()
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now))
        AbstractLogger.__call__(self, '%s.%02d %s: %s' % (timestamp, now % 1 * 100, self._progId, s))


class StreamLogger(AbstractLogger):
    stream = sys.stderr

    def init(self, *priv):
        try:
            handler = logging.StreamHandler(self.stream)

        except AttributeError:
            raise SnmpfwdError(
                'Stream logger failure: %s' % sys.exc_info()[1]
            )

        handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))

        self._logger.addHandler(handler)


class StdoutLogger(StreamLogger):
    stream = sys.stdout


class StderrLogger(StreamLogger):
    stream = sys.stderr


class NullLogger(AbstractLogger):
    def init(self, *priv):
        handler = logging.NullHandler()
        self._logger.addHandler(handler)

    def __call__(self, s):
        pass

methodsMap = {
    'syslog': SyslogLogger,
    'file': FileLogger,
    'stdout': StdoutLogger,
    'stderr': StderrLogger,
    'null': NullLogger
}

levelsMap = {
    'debug': LOG_DEBUG,
    'info': LOG_INFO,
    'error': LOG_ERROR,
}

msg = lambda x: None

logLevel = LOG_INFO


def error(message, ctx=''):
    if logLevel <= LOG_ERROR:
      msg('ERROR %s %s' % (message, ctx))


def info(message, ctx=''):
    if logLevel <= LOG_INFO:
        msg('INFO %s %s' % (message, ctx))


def debug(message, ctx=''):
    if logLevel <= LOG_DEBUG:
        msg('DEBUG %s %s' % (message, ctx))


def setLevel(level):
    global logLevel

    try:
        logLevel = levelsMap[level]

    except KeyError:
        raise SnmpfwdError('Unknown log level "%s", known levels are: %s' % (level, ', '.join(levelsMap)))


def setLogger(progId, *priv, **options):
    global msg

    try:
        if not isinstance(msg, AbstractLogger) or options.get('force'):
            msg = methodsMap[priv[0]](progId, *priv[1:])

    except KeyError:
        raise SnmpfwdError('Unknown logging method "%s", known methods are: %s' % (priv[0], ', '.join(methodsMap.keys())))
