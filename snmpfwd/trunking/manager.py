#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
from snmpfwd.trunking import client, server
from snmpfwd import log, error


class TrunkingManager(object):
    def __init__(self, dataCbFun):
        self.__clients = {}
        self.__runningServersTrunkMap = {}
        self.__runningServersConnMap = {}
        self.__runningClientsTrunkMap = {}
        self.__runningClientsConnMap = {}
        self.__pingPeriods = {}
        self.__upcomingPings = {}
        self.__unconfirmedPings = {}
        self.__serial = 0
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

    def setupTrunks(self, timeNow):
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

    def __monitorTrunksCbFun(self, msg, cbCtx):
        trunkId, expectedSerial = cbCtx
        if msg['serial'] == expectedSerial:
            if trunkId in self.__unconfirmedPings:
                del self.__unconfirmedPings[trunkId]

    def __monitorTrunks(self, timeNow, runningConnections, runningConnectionsMap):
        for trunkId in tuple(runningConnections):
            pingPeriod = self.__pingPeriods[trunkId]
            if not pingPeriod:
                continue

            nextPingAt = self.__upcomingPings.get(trunkId, timeNow)

            if nextPingAt > timeNow:
                continue

            self.__upcomingPings[trunkId] = timeNow + pingPeriod

            connection = runningConnections[trunkId]

            if trunkId in self.__unconfirmedPings:
                log.error('closing unresponsive trunk %s %s' % (trunkId, connection))
                connection.close()
                del runningConnectionsMap[connection]
                del runningConnections[trunkId]
                del self.__unconfirmedPings[trunkId]
                continue

            connection.sendPing(self.__serial, self.__monitorTrunksCbFun, (trunkId, self.__serial))
            self.__unconfirmedPings[trunkId] = True

        self.__serial += 1

    def monitorTrunks(self, timeNow):
        self.__monitorTrunks(
            timeNow, self.__runningClientsTrunkMap, self.__runningClientsConnMap
        )
        self.__monitorTrunks(
            timeNow, self.__runningServersTrunkMap, self.__runningServersConnMap
        )

    def addClient(self, trunkId, localEndpoint, remoteEndpoint, pingPeriod, secret):
        if trunkId in self.__clients or trunkId in self.__runningServersTrunkMap:
            raise error.SnmpfwdError('Trunk %s already registered' % trunkId)
        self.__clients[trunkId] = localEndpoint, remoteEndpoint, secret, self.__proxyDataCbFun
        self.__pingPeriods[trunkId] = pingPeriod

    def __proxyDataCbFun(self, connection, msgId, msg):
        if connection in self.__runningServersConnMap:
            trunkId = self.__runningServersConnMap[connection]
        elif connection in self.__runningClientsConnMap:
            trunkId = self.__runningClientsConnMap[connection]
        else:
            log.error('data message from unknown connection %s ignored' % connection)
            return

        self.__dataCbFun(trunkId, msgId, msg)
        
    def __ctlCbFun(self, connection, msg, cbCtx):
        if msg:
            trunkId = str(msg['trunk-id'])
            pingPeriod = cbCtx
            if trunkId in self.__runningServersTrunkMap or \
                    trunkId in self.__runningClientsTrunkMap:
                log.error('duplicate trunk %s during negotiation with %s' % (trunkId, connection))
                connection.close()
                return

            log.info('registering connection %s as trunk %s' % (connection, trunkId))
            self.__runningServersTrunkMap[trunkId] = connection
            self.__runningServersConnMap[connection] = trunkId
            self.__pingPeriods[trunkId] = pingPeriod

        else:
            if connection in self.__runningServersConnMap:
                trunkId = self.__runningServersConnMap[connection]
            else:
                log.error('control message from unknown connection %s ignored' % connection)
                return
                
            log.info('unregistering connection %s (trunk %s)' % (self.__runningServersTrunkMap[trunkId], trunkId))
            del self.__runningServersTrunkMap[trunkId]
            del self.__runningServersConnMap[connection]

    def addServer(self, localEndpoint, pingPeriod, secret):
        server.TrunkingSuperServer(
            localEndpoint, secret, self.__proxyDataCbFun, self.__ctlCbFun, pingPeriod
        )
