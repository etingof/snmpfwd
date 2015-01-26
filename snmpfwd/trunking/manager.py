from snmpfwd.trunking import client, server
from snmpfwd import log, error

class TrunkingManager:
    def __init__(self, dataCbFun):
        self.__clients = {}
        self.__runningServers = {}
        self.__runningClients = {}
        self.__dataCbFun = dataCbFun

    def sendReq(self, trunkId, req, cbFun, cbCtx):
        if trunkId in self.__runningServers:
            trunk = self.__runningServers[trunkId]
        elif trunkId in self.__runningClients:
            trunk = self.__runningClients[trunkId]
        else:
            raise error.SnmpfwdError('Unknown trunk ID %s' % trunkId)

        return trunk.sendReq(req, cbFun, cbCtx)

    def sendRsp(self, trunkId, msgId, rsp):
        if trunkId in self.__runningServers:
            trunk = self.__runningServers[trunkId]
        elif trunkId in self.__runningClients:
            trunk = self.__runningClients[trunkId]
        else:
            raise error.SnmpfwdError('Unknown trunk ID %s' % trunkId)

        return trunk.sendRsp(msgId, rsp)

    def monitorTrunks(self, timeNow):
        for trunkId in self.__clients:
            if trunkId in self.__runningClients and \
                    not self.__runningClients[trunkId].isUp:
                self.__runningClients[trunkId].close()
                del self.__runningClients[trunkId]
            if trunkId not in self.__runningClients:
                self.__runningClients[trunkId] = client.TrunkingClient(
                    *self.__clients[trunkId]
                )
                self.__runningClients[trunkId].sendAnnouncement(trunkId)

    def addClient(self, trunkId, localEndpoint, remoteEndpoint, secret):
        if trunkId in self.__clients or trunkId in self.__runningServers:
            raise error.SnmpfwdError('Trunk %s already registered' % trunkId)
        self.__clients[trunkId] = localEndpoint, remoteEndpoint, secret, self.__proxyDataCbFun

    def __proxyDataCbFun(self, connection, msgId, msg):
        for k,v in self.__runningServers.items()+self.__runningClients.items():
            if v == connection:
                trunkId = k
                break
        else:
            log.msg('data message from unknown connection %s ignored' % connection)
            return

        self.__dataCbFun(trunkId, msgId, msg)
        
    def __ctlCbFun(self, connection, msg=None):
        if msg:
            if msg['trunk-id'] in self.__runningServers or \
                    msg['trunk-id'] in self.__runningClients:
                log.msg('duplicate trunk %s during negotiation with %s' % (msg['trunk-id'], connection))
                connection.close()
                return

            log.msg('registering connection %s as trunk %s' % (connection, msg['trunk-id']))        
            self.__runningServers[msg['trunk-id']] = connection

        else:
            for k,v in self.__runningServers.items():
                if v == connection:
                    trunkId = k
                    break
            else:
                log.msg('control message from unknown connection %s ignored' % connection)
                return
                
            log.msg('unregistering connection %s (trunk %s)' % (self.__runningServers[trunkId], trunkId))
            del self.__runningServers[trunkId]

    def addServer(self, localEndpoint, secret):
        server.TrunkingSuperServer(
            localEndpoint, secret, self.__proxyDataCbFun, self.__ctlCbFun
        )
