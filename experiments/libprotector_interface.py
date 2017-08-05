#Interface for using libprotector
import ctypes
lib = ctypes.cdll.LoadLibrary('./../libprotector.so')

class KMS():
    def __init__(self):
        res = lib.libprotector_KMS_new()
        self.kms = res
    
#    def __del__(self):
#        lib.libprotector_KMS_destroy(self.kms)
    
    def initKMS(self, keysize):
        return lib.libprotector_KMS_InitKMS(self.kms, keysize)
    
    def addUser(self):
        return lib.libprotector_KMS_addUser(self.kms)
    
    def getProxyKey(self, user_id):
        return ctypes.c_char_p(lib.libprotector_KMS_getProxyKey(self.kms, user_id)).value
    
    def getClientKey(self, user_id):
        return ctypes.c_char_p(lib.libprotector_KMS_getClientKey(self.kms, user_id)).value
    
    def getPrimeQ(self):
        return ctypes.c_char_p(lib.libprotector_KMS_getPrimeQ(self.kms)).value


def getPrimeQ():
    return ctypes.c_char_p(lib.retrieveKeyFromServer(ctypes.c_char_p("primeQ"))).value;

def getServerKey(user_id):
    return ctypes.c_char_p(lib.retrieveKeyFromServer(ctypes.c_char_p("serverK:{0}".format(user_id)))).value;

def getUserKey(user_id):
    return ctypes.c_char_p(lib.retrieveKeyFromServer(ctypes.c_char_p("userK:{0}".format(user_id)))).value;

def user_enc_w_keys(text, user_key, prime_q):
    res = lib.libprotector_EncryptUserContentWithKeys(ctypes.c_char_p(text), ctypes.c_uint(len(text)), ctypes.c_char_p(user_key), ctypes.c_char_p(prime_q))
    return ctypes.c_char_p(res).value

def user_enc(text):
    return ctypes.c_char_p(lib.libprotector_EncryptUserContent(ctypes.c_char_p(text), ctypes.c_uint(len(text)))).value

def ccn_re_enc_w_keys(t1, t2, server_key, prime_q):
    res = lib.libprotector_ReEncryptUserContentWithKeys(ctypes.c_char_p(t1), ctypes.c_uint(t2), ctypes.c_char_p(server_key), ctypes.c_char_p(prime_q))
    return ctypes.c_char_p(res).value 
def ccn_re_enc(t1, t2):
    return lib.libprotector_ReEncryptUserContent(ctypes.c_char_p(t1), ctypes.c_uint(t2))
    

def ccn_pre_dec_w_keys(t, server_key, prime_q):
    res = lib.libprotector_DecryptContentWithKeys(ctypes.c_char_p(t), ctypes.c_char_p(server_key), ctypes.c_char_p(prime_q));
    
    return ctypes.c_char_p(res).value

def ccn_pre_dec(t):
    return lib.libprotector_DecryptContent(ctypes.c_char_p(t));

def client_dec_w_keys(t, user_key, prime_q):
    res = lib.libprotector_ReDecryptContentWithKeys(ctypes.c_char_p(t), ctypes.c_char_p(user_key), ctypes.c_char_p(prime_q));
    
    return ctypes.c_char_p(res).value
def client_dec(t):
    return lib.libprotector_ReDecryptContent(ctypes.c_char_p(t));
    
if __name__ == '__main__':
    for i in range(1, 5):
        k = KMS()
        k.initKMS(256*(2**i))
        k.addUser()
        print 256*(2**i)
        print k.getProxyKey(0)
        print k.getClientKey(0)
        print k.getPrimeQ()
        print
