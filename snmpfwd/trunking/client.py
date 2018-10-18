#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import socket
import asyncore
import traceback
import sys
from snmpfwd import log, next, error
from snmpfwd.trunking import protocol
from pyasn1.compat.octets import null


class TrunkingClient(asyncore.dispatcher_with_send):
    isUp = False

    def __init__(self, localEndpoint, remoteEndpoint, secret, dataCbFun):
        localAf, self.__localEndpoint = localEndpoint[0], localEndpoint[1:]
        remoteAf, self.__remoteEndpoint = remoteEndpoint[0], remoteEndpoint[1:]
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__pendingReqs = {}
        self.__pendingCounter = 0
        self.__input = null
        self.__announcementData = null

        if localAf != remoteAf:
            raise error.SnmpfwdError('%s: mismatching address family')

        asyncore.dispatcher_with_send.__init__(self)

        try:
            self.create_socket(localAf, socket.SOCK_STREAM)
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 65535
            )
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 65535
            )
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.bind(self.__localEndpoint)
            self.connect(self.__remoteEndpoint)

        except socket.error:
            raise error.SnmpfwdError('%s socket error: %s' % (self, sys.exc_info()[1]))

        log.info('%s: initiated trunk client connection from %s to %s...' % (self, localEndpoint, remoteEndpoint))

    def sendReq(self, req, cbFun, cbCtx):
        msgId = next.getId()
        self.send(protocol.prepareRequestData(msgId, req, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx
        return msgId

    def sendRsp(self, msgId, rsp):
        self.send(protocol.prepareResponseData(msgId, rsp, self.__secret))

    def sendAnnouncement(self, trunkId):
        self.__announcementData = protocol.prepareAnnouncementData(
            trunkId, self.__secret
        )

    def sendPing(self, serial, cbFun, cbCtx):
        msgId = next.getId()
        self.send(protocol.preparePingData(msgId, serial, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx

    def __ackPingCbFun(self, msgId, req):
        self.send(protocol.preparePongData(msgId, req['serial'], self.__secret))

    def __str__(self):
        return '%s at %s, peer %s' % (self.__class__.__name__, ':'.join([str(x) for x in self.__localEndpoint]), ':'.join([str(x) for x in self.__remoteEndpoint]))

    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__, self.__localEndpoint, self.__remoteEndpoint
        )

    # asyncore API

    def handle_connect(self):
        if self.isUp:
            return
        self.isUp = True

        if self.__announcementData:
            self.send(self.__announcementData)
            self.__announcementData = null
            log.debug('%s: trunk announcement sent' % (self,))

        log.info('%s: client is now connected' % (self,))
        
    def handle_read(self):
        chunk = self.recv(65535)
        if not chunk:
            self.handle_close()
        self.__input += chunk
        while self.__input:
            msgId, contentId, msg, self.__input = protocol.prepareDataElements(
                self.__input, self.__secret
            )
            if msgId is None:
                if self.__pendingCounter > 5:
                    log.error('%s: incomplete trunk message pending for too long, closing connection' % (self,))
                    self.close()
                    return
                else:
                    self.__pendingCounter += 1
                return

            self.__pendingCounter = 0

            if contentId == protocol.MSG_TYPE_REQUEST:
                self.__dataCbFun(self, msgId, msg)
            elif contentId == protocol.MSG_TYPE_RESPONSE:
                if msgId in self.__pendingReqs:
                    cbFun, cbCtx = self.__pendingReqs.pop(msgId)
                    cbFun(msgId, msg, cbCtx)
            elif contentId == protocol.MSG_TYPE_PING:
                    self.__ackPingCbFun(msgId, msg)
            elif contentId == protocol.MSG_TYPE_PONG:
                if msgId in self.__pendingReqs:
                    cbFun, cbCtx = self.__pendingReqs.pop(msgId)
                    cbFun(msg, cbCtx)
            else:
                log.error('%s: unknown trunk message content-id %s ignored' % (self, contentId))
            
    def handle_close(self):
        log.info('%s: connection with %s closed' % (self, ':'.join([str(x) for x in self.__remoteEndpoint])))
        self.isUp = False
        self.close()

    def handle_error(self, *info):
        exc_info = sys.exc_info()
        log.error('%s: connection with %s broken: %s' % (self, ':'.join([str(x) for x in self.__remoteEndpoint]), exc_info[1]))
        if exc_info and not isinstance(exc_info[1], socket.error):
            for line in traceback.format_exception(*exc_info):
                log.error(line.replace('\n', ';'))
        self.handle_close()
