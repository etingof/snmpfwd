from Crypto import Random
from Crypto.Cipher import AES
from pyasn1.compat.octets import int2oct, oct2int

class AESCipher:
    def pad(self, s, BS=16):
        return s + (BS - len(s) % BS) * int2oct(BS - len(s) % BS)

    def unpad(self, s, BS=16):
        return s[0:-oct2int(s[-1])]
    
    def encrypt(self, key, raw):
        raw = self.pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw) 

    def decrypt(self, key, enc):
        iv = enc[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:]))

encrypt = AESCipher().encrypt
decrypt = AESCipher().decrypt
