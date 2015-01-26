from snmpfwd.trunking import client, server
from snmpfwd import log, error

class TrunkingManager:
    def __init__(self, dataCbFun):
        self.__clients = {}
        self.__runningServersTrunkMap = {}
        self.__runningServersConnMap = {}
        self.__runningClientsTrunkMap = {}
        self.__runningClientsConnMap = {}
        self.__dataCbFun = dataCbFun

    def sendReq(self, trunkId, req, cbFun, cbCtx):
        if trunkId in self.__runningServersTrunkMap:
            trunk = self.__runningServersTrunkMap[trunkId]
        elif trunkId in self.__runningClientsTrunkMap:
            trunk = self.__runningClientsTrunkMap[trunkId]
        else:
            raise error.SnmpfwdError('Unknown trunk ID %s' % trunkId)

        return trunk.sendReq(req, cbFun, cbCtx)

    def sendRsp(self, trunkId, msgId, rsp):
        if trunkId in self.__runningServersTrunkMap:
            trunk = self.__runningServersTrunkMap[trunkId]
        elif trunkId in self.__runningClientsTrunkMap:
            trunk = self.__runningClientsTrunkMap[trunkId]
        else:
            raise error.SnmpfwdError('Unknown trunk ID %s' % trunkId)

        return trunk.sendRsp(msgId, rsp)

    def monitorTrunks(self, timeNow):
        for trunkId in self.__clients:
            if trunkId in self.__runningClientsTrunkMap and \
                    not self.__runningClientsTrunkMap[trunkId].isUp:
                self.__runningClientsTrunkMap[trunkId].close()
                del self.__runningClientsConnMap[self.__runningClientsTrunkMap[trunkId]]
                del self.__runningClientsTrunkMap[trunkId]
            if trunkId not in self.__runningClientsTrunkMap:
                self.__runningClientsTrunkMap[trunkId] = client.TrunkingClient(
                    *self.__clients[trunkId]
                )
                self.__runningClientsConnMap[self.__runningClientsTrunkMap[trunkId]] = trunkId
                self.__runningClientsTrunkMap[trunkId].sendAnnouncement(trunkId)

    def addClient(self, trunkId, localEndpoint, remoteEndpoint, secret):
        if trunkId in self.__clients or trunkId in self.__runningServersTrunkMap:
            raise error.SnmpfwdError('Trunk %s already registered' % trunkId)
        self.__clients[trunkId] = localEndpoint, remoteEndpoint, secret, self.__proxyDataCbFun

    def __proxyDataCbFun(self, connection, msgId, msg):
        if connection in self.__runningServersConnMap:
            trunkId = self.__runningServersConnMap[connection]
        elif connection in self.__runningClientsConnMap:
            trunkId = self.__runningClientsConnMap[connection]
        else:
            log.msg('data message from unknown connection %s ignored' % connection)
            return

        self.__dataCbFun(trunkId, msgId, msg)
        
    def __ctlCbFun(self, connection, msg=None):
        if msg:
            trunkId = str(msg['trunk-id'])
            if trunkId in self.__runningServersTrunkMap or \
                    trunkId in self.__runningClientsTrunkMap:
                log.msg('duplicate trunk %s during negotiation with %s' % (trunkId, connection))
                connection.close()
                return

            log.msg('registering connection %s as trunk %s' % (connection, trunkId))        
            self.__runningServersTrunkMap[trunkId] = connection
            self.__runningServersConnMap[connection] = trunkId

        else:
            if connection in self.__runningServersConnMap:
                trunkId = self.__runningServersConnMap[connection]
            else:
                log.msg('control message from unknown connection %s ignored' % connection)
                return
                
            log.msg('unregistering connection %s (trunk %s)' % (self.__runningServersTrunkMap[trunkId], trunkId))
            del self.__runningServersTrunkMap[trunkId]
            del self.__runningServersConnMap[connection]

    def addServer(self, localEndpoint, secret):
        server.TrunkingSuperServer(
            localEndpoint, secret, self.__proxyDataCbFun, self.__ctlCbFun
        )
