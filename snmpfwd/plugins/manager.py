#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import os
import sys
from snmpfwd.plugins.status import *
from snmpfwd import log, error


class PluginManager(object):
    def __init__(self, path, progId, apiVer):
        self.__path = path
        self.__progId = progId
        self.__apiVer = apiVer
        self.__plugins = {}

    def hasPlugin(self, pluginId):
        return pluginId in self.__plugins

    def loadPlugin(self, pluginId, pluginModuleName, pluginOptions):
        if pluginId in self.__plugins:
            raise error.SnmpfwdError('duplicate plugin ID %s' % pluginId)

        for pluginModulesDir in self.__path:
            log.info('scanning "%s" directory for plugin modules...' % pluginModulesDir)
            if not os.path.exists(pluginModulesDir):
                log.error('directory "%s" does not exist' % pluginModulesDir)
                continue

            modPath = os.path.join(pluginModulesDir, pluginModuleName + '.py')
            if not os.path.exists(modPath):
                log.error('Variation module "%s" not found' % modPath)
                continue
            
            ctx = {'modulePath': modPath,
                   'moduleContext': {},
                   'moduleOptions': pluginOptions}

            modData = open(modPath).read()

            try:
                exec(compile(modData, modPath, 'exec'), ctx)

            except Exception:
                raise error.SnmpfwdError('plugin module "%s" execution failure: %s' % (modPath, sys.exc_info()[1]))

            else:
                pluginModule = ctx
                try:
                    if self.__progId not in pluginModule['hostProgs']:
                        log.error('ignoring plugin module "%s" (unmatched program ID)' % modPath)
                        continue

                    if self.__apiVer not in pluginModule['apiVersions']:
                        log.error('ignoring plugin module "%s" (incompatible API version)' % modPath)
                        continue
                except KeyError:
                    log.error('ignoring plugin module "%s" (missing versioning info)' % modPath)
                    continue
                    
                self.__plugins[pluginId] = pluginModule

                log.info('plugin module "%s" loaded' % modPath)
                break

        else:
            raise error.SnmpfwdError('plugin module "%s" not found in search path(s): %s' % (pluginModuleName, ', '.join(self.__path)))

    def processCommandRequest(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processCommandRequest' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processCommandRequest']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)

    def processCommandResponse(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processCommandResponse' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processCommandResponse']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)

    def processNotificationRequest(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processNotificationRequest' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processNotificationRequest']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)

    def processNotificationResponse(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processNotificationResponse' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processNotificationResponse']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)
