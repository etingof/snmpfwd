#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
try:
    from Cryptodome import Random
    from Cryptodome.Cipher import AES

    from pyasn1.compat.octets import int2oct, oct2int, str2octs

except ImportError:

    from snmpfwd.error import SnmpfwdError


    class NoCipher(object):
        msg = ('Trunk encryption is not available. Make sure '
               'to install the `pycryptodomex` package')

        def encrypt(self, key, raw):
            raise SnmpfwdError(self.msg)

        def decrypt(self, key, raw):
            raise SnmpfwdError(self.msg)

    Cipher = NoCipher

else:

    class AESCipher(object):
        @staticmethod
        def pad(s, BS=16):
            return s + (BS - len(s) % BS) * int2oct(BS - len(s) % BS)

        @staticmethod
        def unpad(s):
            return s[0:-oct2int(s[-1])]

        def encrypt(self, key, raw):
            raw = self.pad(raw)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(str2octs(key), AES.MODE_CBC, iv)
            return iv + cipher.encrypt(raw)

        def decrypt(self, key, enc):
            iv = enc[:16]
            cipher = AES.new(str2octs(key), AES.MODE_CBC, iv)
            return self.unpad(cipher.decrypt(enc[16:]))

    Cipher = AESCipher


encrypt = Cipher().encrypt
decrypt = Cipher().decrypt
