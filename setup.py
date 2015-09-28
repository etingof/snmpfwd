#!/usr/bin/env python
"""SNMP Proxy Forwarder can act as an application-level firewall
   or SNMP protocol translator that let SNMPv1/v2c entities to talk
   to SNMPv3 ones or vice-versa.
"""
import sys
import os
import glob

classifiers = """\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: Developers
Intended Audience :: Education
Intended Audience :: Information Technology
Intended Audience :: Science/Research
Intended Audience :: System Administrators
Intended Audience :: Telecommunications Industry
License :: OSI Approved :: BSD License
Natural Language :: English
Operating System :: OS Independent
Programming Language :: Python :: 2
Programming Language :: Python :: 3
Topic :: Communications
Topic :: System :: Monitoring
Topic :: System :: Networking :: Monitoring
"""

def howto_install_distribute():
    print("""
   Error: You need the distribute Python package!

   It's very easy to install it, just type (as root on Linux):

   wget http://python-distribute.org/distribute_setup.py
   python distribute_setup.py

   Then you could make eggs from this package.
""")

def howto_install_setuptools():
    print("""
   Error: You need setuptools Python package!

   It's very easy to install it, just type (as root on Linux):

   wget http://peak.telecommunity.com/dist/ez_setup.py
   python ez_setup.py

   Then you could make eggs from this package.
""")

try:
    from setuptools import setup
    params = {
        'install_requires': [ 'pysnmp>=4.3.0' ],
        'zip_safe': True
        }
except ImportError:
    for arg in sys.argv:
        if "egg" in arg:
            if sys.version_info[0] > 2:
                howto_install_distribute()
            else:
                howto_install_setuptools()
            sys.exit(1)
    from distutils.core import setup
    params = {}
    if sys.version_info[:2] > (2, 4):
        params['requires'] = [ 'pysnmp(>=4.3.0)' ]

doclines = [ x.strip() for x in __doc__.split('\n') if x ]

params.update( {
    'name': "snmpfwd",
    'version':  open(os.path.join('snmpfwd', '__init__.py')).read().split('\'')[1],
    'description': doclines[0],
    'long_description': ' '.join(doclines[1:]),
    'maintainer': 'Ilya Etingof <ilya@snmplabs.com>',
    'author': "Ilya Etingof",
    'author_email': "ilya@snmplabs.com",
    'url': "http://sourceforge.net/projects/snmpfwd/",
    'platforms': ['any'],
    'classifiers': [ x for x in classifiers.split('\n') if x ],
    'scripts': [ 'scripts/snmpfwd-client.py', 'scripts/snmpfwd-server.py' ],
    'packages': [ 'snmpfwd', 'snmpfwd.trunking', 'snmpfwd.plugins' ],
    'license': "BSD"
  } )


# install stock variation modules as data_files
params['data_files'] = [
    ( 'snmpfwd/' + 'plugins', glob.glob(os.path.join('plugins', '*.py')) )
]

if 'py2exe' in sys.argv:
    import py2exe
    # fix executables
    params['console'] = params['scripts']
    del params['scripts']

    # pysnmp used by snmpfwd dynamically loads some of its *.py files
    params['options'] = {
        'py2exe': {
            'includes': [
                'pysnmp.smi.mibs.*',
                'pysnmp.smi.mibs.instances.*'
            ],
            'bundle_files': 1,
            'compressed': True
        }
    }

    params['zipfile'] = None

    del params['data_files']  # no need to store these in .exe

    # additional modules used by snmpfwd but not seen by py2exe
    for m in ('random',):
        try:
            __import__(m)
        except ImportError:
            continue
        else:
            params['options']['py2exe']['includes'].append(m)

    print("!!! Make sure your pysnmp/pyasn1 packages are NOT .egg'ed!!!")

setup(**params)

