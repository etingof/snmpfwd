import socket
import asyncore
import traceback
import sys
from snmpfwd import log, next, error
from snmpfwd.trunking import protocol
from pyasn1.compat.octets import null

class TrunkingSuperServer(asyncore.dispatcher):
    def __init__ (self, localEndpoint, secret, dataCbFun, ctlCbFun):
        self.__localEndpoint = localEndpoint
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__ctlCbFun = ctlCbFun
        asyncore.dispatcher.__init__(self)

        try: 
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 65535
            )
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 65535
            )
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.bind(localEndpoint)
            self.listen(10)
        except socket.error:
            raise error.SnmpfwdError('%s socket error: %s' % (self, sys.exc_info()[1]))
            log.msg('%s: listening...' % self)

    def __str__(self):
        return '%s at %s' % (self.__class__.__name__, ':'.join([str(x) for x in self.__localEndpoint]))
        
    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.__localEndpoint)

    # asyncore API

    def handle_accept(self):
        try:
            sock, remoteEndpoint = self.accept()
        except socket.error:
            log.msg('%s accept() failed: %s' % (self, sys.exc_info()[1]))
            return

        log.msg('%s new connection from %s' % (self, ':'.join([str(x) for x in remoteEndpoint])))

        TrunkingServer(sock,
                       self.__localEndpoint, remoteEndpoint, self.__secret,
                       self.__dataCbFun, self.__ctlCbFun)
        
    def handle_error(self, *info):
        exc_info = sys.exc_info()
        log.msg('%s: error: %s' % (self, exc_info[1]))
        if exc_info and not isinstance(exc_info[1], socket.error):
            for line in traceback.format_exception(*exc_info):
                log.msg(line.replace('\n', ';'))
        self.handle_close()


class TrunkingServer(asyncore.dispatcher_with_send):
    def __init__ (self, sock, localEndpoint, remoteEndpoint, secret,
                  dataCbFun, ctlCbFun):
        self.__localEndpoint = localEndpoint
        self.__remoteEndpoint = remoteEndpoint
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__ctlCbFun = ctlCbFun
        self.__pendingReqs = {}
        self.__pendingCounter = 0
        self.__input = null
        self.socket = None  # asyncore strangeness
        asyncore.dispatcher_with_send.__init__(self, sock)

        try: 
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 65535
            )
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 65535
            )
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except socket.error:
            raise error.SnmpfwdError('%s socket error: %s' % (self, sys.exc_info()[1]))
        else:
            log.msg('%s: serving new connection...' % (self,))

    def __str__(self):
        return '%s at %s, peer %s' % (self.__class__.__name__, ':'.join([str(x) for x in self.__localEndpoint]), ':'.join([str(x) for x in self.__remoteEndpoint]))

    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__, self.__localEndpoint, self.__remoteEndpoint
        )

    def sendReq(self, req, cbFun, cbCtx):
        msgId = next.getId()
        self.send(protocol.prepareRequestData(msgId, req, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx

    def sendRsp(self, msgId, rsp):
        self.send(protocol.prepareResponseData(msgId, rsp, self.__secret))
        
    # asyncore API

    def handle_read(self):
        chunk = self.recv(65535)
        if not chunk:
            self.handle_close()
        self.__input += chunk
        while self.__input:
            msgId, contentId, msg, self.__input = protocol.prepareDataElements(self.__input, self.__secret)

            if msgId is None:
                if self.__pendingCounter > 5:
                    log.msg('incomplete message pending for too long, closing connection with %s' % (self,))
                    self.close()
                    return
                else:
                    self.__pendingCounter += 1
                return

            self.__pendingCounter = 0

            if contentId == 0:   # request
                self.__dataCbFun(self, msgId, msg)
            elif contentId == 1: # response
                if msgId in self.__pendingReqs:
                    cbFun, cbCtx = self.__pendingReqs.pop(msgId)
                    cbFun(msg, cbCtx)
            elif contentId == 2: # announcement
                self.__ctlCbFun(self, msg)
            else:
                log.msg('unknown message content-id %s from %s ignored' % (contentId, self))
                
    def handle_close(self):
        log.msg('%s: connection closed' % (self,))
        self.__ctlCbFun(self)
        self.close()
        
    def handle_error(self, *info):
        exc_info = sys.exc_info()
        log.msg('connection with %s broken: %s' % (self.__remoteEndpoint, exc_info[1]))
        if exc_info and not isinstance(exc_info[1], socket.error):
            for line in traceback.format_exception(*exc_info):
                log.msg(line.replace('\n', ';'))
        self.handle_close()
