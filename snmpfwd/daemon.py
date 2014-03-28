# UNIX-specific process daemonization tools
import sys
from snmpfwd import error

if sys.platform[:3] == 'win':
    def daemonize(pidfile):
        raise error.SnmpfwdError('Windows is not inhabited with daemons!')
    def dropPrivileges(uname, gname):
        return
else:
    import os, pwd, grp, atexit, signal, tempfile

    def daemonize(pidfile):
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                os._exit(0) 
        except OSError:
            raise error.SnmpfwdError('ERROR: fork #1 failed: %s' % sys.exc_info()[1])

        # decouple from parent environment
        try:
            os.chdir('/') 
            os.setsid() 
        except OSError:
            pass
        os.umask(0) 
            
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                os._exit(0) 
        except OSError:
            raise error.SnmpfwdError('ERROR: fork #2 failed: %s' % sys.exc_info()[1])

        def signal_cb(s,f):
            raise KeyboardInterrupt
        for s in signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT:
            signal.signal(s, signal_cb)
             
        # write pidfile
        def atexit_cb():
            try:
                if pidfile: os.remove(pidfile)
            except OSError:
                pass
        atexit.register(atexit_cb)

        try:
            if pidfile:
                fd, nm = tempfile.mkstemp(dir=os.path.dirname(pidfile))
                os.write(fd, '%d\n' % os.getpid())
                os.close(fd)
                os.rename(nm, pidfile)
        except:
            raise error.SnmpfwdError('Failed to create PID file %s: %s' % (pidfile, sys.exc_info()[1]))

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
          
    def dropPrivileges(uname, gname):
        if os.getuid() != 0:
            if uname and uname != pwd.getpwnam(uname).pw_name or \
                    gname and gname != grp.getgrnam(gname).gr_name:
                raise error.SnmpfwdError('Process is running under different UID/GID')
            else:
                return
        else:
            if not uname or not gname:
                raise error.SnmpfwdError('Must drop priveleges to a non-priveleged user&group')

        try:
            runningUid = pwd.getpwnam(uname).pw_uid
            runningGid = grp.getgrnam(gname).gr_gid
        except Exception:
            raise error.SnmpfwdError('getpwnam()/getgrnam() failed for %s/%s: %s' % (uname, gname, sys.exc_info()[1]))

        try:
            os.setgroups([])
        except Exception:
            raise error.SnmpfwdError('setgroups() failed: %s' % sys.exc_info()[1])

        try:
            os.setgid(runningGid)
            os.setuid(runningUid)
        except Exception:
            raise error.SnmpfwdError('setgid()/setuid() failed for %s/%s: %s' % (runningGid, runningUid, sys.exc_info()[1]))

        os.umask(63)  # 0077
