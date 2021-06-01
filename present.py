import ctypes as CTYPES
import json as JSON

class present:
    
    def __init__(self, key):
        data = JSON.load(open("./path.json", 'r'))
        self.lib = CTYPES.CDLL(f"{data['path']}")
        self.lib.present_encrypt.argtypes = [CTYPES.POINTER(CTYPES.c_ubyte),CTYPES.POINTER(CTYPES.c_ubyte),CTYPES.POINTER(CTYPES.c_ubyte)]
        self.lib.present_decrypt.argtypes = [CTYPES.POINTER(CTYPES.c_ubyte),CTYPES.POINTER(CTYPES.c_ubyte),CTYPES.POINTER(CTYPES.c_ubyte)]
        self.key = key

    def encrypt(self, plain) -> list[int]:
        PLAIN = (CTYPES.c_ubyte * 8)(*plain)
        KEY = (CTYPES.c_ubyte * 10)(*(self.key))
        ans = [0, 0, 0, 0, 0, 0, 0, 0]
        ANS = (CTYPES.c_ubyte * 8)(*ans)
        self.lib.present_encrypt(PLAIN, KEY, ANS)
        return ANS

    def decrypt(self, cipher) -> list[int]:
        CIPHER = (CTYPES.c_ubyte * 8)(*cipher)
        KEY = (CTYPES.c_ubyte * 10)(*(self.key))
        ans = [0, 0, 0, 0, 0, 0, 0, 0]
        ANS = (CTYPES.c_ubyte * 8)(*ans)
        self.lib.present_decrypt(CIPHER, KEY, ANS)
        return ANS