
def expandMacros(s, d):
    for k in d:
        if not s or '${' not in s:
            return s
        pat = '${%s}' % k
        s = s.replace(pat, str(d[k]))
    return s
