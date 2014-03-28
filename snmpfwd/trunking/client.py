import socket
import asyncore
import traceback
import sys
from snmpfwd import log, next, error
from snmpfwd.trunking import protocol

class TrunkingClient(asyncore.dispatcher_with_send):
    isUp = False
    def __init__ (self, localEndpoint, remoteEndpoint, secret, dataCbFun):
        self.__localEndpoint = localEndpoint
        self.__remoteEndpoint = remoteEndpoint
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__pendingReqs = {}
        self.__input = ''
        self.__announcementData = ''
        asyncore.dispatcher_with_send.__init__(self)

        try: 
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 65535
            )
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 65535
            )
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.bind(localEndpoint)
            self.connect(remoteEndpoint)
        except socket.error:
            raise error.SnmpfwdError('%s socket error: %s' % (self, sys.exc_info()[1]))
        log.msg('initiated trunk client connection from %s to %s...' % (localEndpoint, remoteEndpoint))

    def sendReq(self, req, cbFun, cbCtx):
        msgId = next.getId()
        self.send(protocol.prepareRequestData(msgId, req, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx

    def sendRsp(self, msgId, rsp):
        self.send(protocol.prepareResponseData(msgId, rsp, self.__secret))

    def sendAnnouncement(self, trunkId):
        self.__announcementData = protocol.prepareAnnouncementData(
            trunkId, self.__secret
        )

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
            self.__announcementData = ''
            log.msg('trunking client %s sent trunk announcement' % self)

        log.msg('trunk client %s is now connected' % self)
        
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
                return

            if contentId == 0:    # request
                self.__dataCbFun(self, msgId, msg)
            elif contentId == 1:  # response
                if msgId in self.__pendingReqs:
                    cbFun, cbCtx = self.__pendingReqs.pop(msgId)
                    cbFun(msg, cbCtx)
            else:
                log.msg('unknown message content-id %s from %s ignored' % (contentId, self))
            
    def handle_close(self):
        self.isUp = False
        log.msg('trunk client connection with %s:%s closed' % self.__remoteEndpoint)
        self.close()

    def handle_error(self, *info):
        log.msg('connection with %s broken: %s' % (self.__remoteEndpoint, info))
        exc_info = sys.exc_info()
        if exc_info:
            for line in traceback.format_exception(*exc_info):
                log.msg(line.replace('\n', ';'))
        self.handle_close ()

# test

if __name__ == '__main__':
    from pysnmp.proto import rfc1905
    from pysnmp.proto.api import v2c

    log.setLogger('snmpfwd', 'stdout')
    tc = TrunkingClient(('127.0.0.1', 1225), 'a'*16)

    def cbFun(msgId, rsp, cbCtx):
        print msgId, rsp

    pdu = rfc1905.GetRequestPDU()
    v2c.apiPDU.setDefaults(pdu)

    tc.sendReq( { 'transport-domain': (1,3,6,1,1,1),
                  'transport-address': '127.0.0.1:161',
                  'security-model': 1,
                  'security-level': 1,
                  'security-name': 'testname',
                  'context-engine-id': '0x010202030304',
                  'context-name': 'mycontext',
                  'pdu': pdu }, cbFun)

    asyncore.loop(1)

