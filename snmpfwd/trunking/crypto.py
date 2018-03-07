#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
from Cryptodome import Random
from Cryptodome.Cipher import AES
from pyasn1.compat.octets import int2oct, oct2int, str2octs


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

encrypt = AESCipher().encrypt
decrypt = AESCipher().decrypt
