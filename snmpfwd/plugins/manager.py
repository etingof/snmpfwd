import os
import sys
from snmpfwd.plugins.status import *
from snmpfwd import log, error

class PluginManager:
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
            log.msg('scanning "%s" directory for plugin modules...' % pluginModulesDir)
            if not os.path.exists(pluginModulesDir):
                log.msg('directory "%s" does not exist' % pluginModulesDir)
                continue

            mod = os.path.join(pluginModulesDir, pluginModuleName + '.py')
            if not os.path.exists(mod):
                log.msg('Variation module "%s" not found' % mod)
                continue
            
            ctx = { 'modulePath': mod,
                    'moduleContext': {},
                    'moduleOptions': pluginOptions }

            try:
                if sys.version_info[0] > 2:
                    exec(compile(open(mod).read(), mod, 'exec'), ctx)
                else:
                    execfile(mod, ctx)

            except Exception:
                raise error.SnmpfwdError('plugin module "%s" execution failure: %s' %  (mod, sys.exc_info()[1]))

            else:
                pluginModule = ctx
                try:
                    if self.__progId not in pluginModule['hostProgs']:
                        log.msg('ignoring plugin module "%s" (unmatched program ID)' % mod)
                        continue

                    if self.__apiVer not in pluginModule['apiVersions']:
                        log.msg('ignoring plugin module "%s" (incompatible API version)' % mod)
                        continue
                except KeyError:
                    log.msg('ignoring plugin module "%s" (missing versioning info)' % mod)
                    continue
                    
                self.__plugins[pluginId] = pluginModule

                log.msg('plugin module "%s" loaded' % mod)
                break

        else:
            raise error.SnmpfwdError('plugin module "%s" not found' % pluginModuleName)

    def processCommandRequest(self, pluginId, snmpEngine, pdu, **context):
        if pluginId not in self.__plugins:
            log.msg('WARNING: skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processCommandRequest' not in self.__plugins[pluginId]:
            return NEXT, pdu

        return self.__plugins[pluginId]['processCommandRequest'](pluginId, snmpEngine, pdu, **context)

    def processCommandResponse(self, pluginId, snmpEngine, pdu, **context):
        if pluginId not in self.__plugins:
            log.msg('WARNING: skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processCommandResponse' not in self.__plugins[pluginId]:
            return NEXT, pdu

        return self.__plugins[pluginId]['processCommandResponse'](pluginId, snmpEngine, pdu, **context)
