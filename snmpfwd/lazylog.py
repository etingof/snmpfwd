from pysnmp.proto.api import v2c


class LazyLogString(object):
    ALIASES = {}
    GROUPINGS = []
    FORMATTERS = {}

    def __init__(self, *contexts):
        self._ctx = {}
        for ctx in contexts:
            self._ctx.update(ctx)
        self._dirty = bool(contexts)
        self._logMsg = ''

    def __str__(self):
        if self._dirty:
            self._dirty = False

            ctx = self._ctx

            self._logMsg = ''

            for grouping in self.GROUPINGS:
                for key in grouping:
                    if key not in ctx:
                        continue

                    val = ctx[key]

                    if key in self.FORMATTERS:
                        val = self.FORMATTERS[key](val)
                    elif isinstance(val, int):
                        val = str(val)
                    else:
                        if val:
                            val = v2c.OctetString(val).prettyPrint()

                    if key in self.ALIASES:
                        key = self.ALIASES[key]

                    self._logMsg += '%s=%s ' % (key, val or '<nil>')

        return self._logMsg

    def update(self, ctx):
        self._ctx.update(ctx)
        self._dirty = True

    @staticmethod
    def prettyVarBinds(pdu):
        if pdu:
            logMsg = pdu.__class__.__name__ + '#'

            for oid, val in v2c.apiPDU.getVarBinds(pdu):
                val = val.prettyPrint()
                if len(val) > 32:
                    val = val[:32] + '...'

                if val:
                    val = repr(val)
                else:
                    val = '<nil>'

                logMsg += '%s:%s' % (oid.prettyPrint(), val) + ','
        else:
            logMsg = '<nil>'

        return logMsg

