#Interface for using libprotector
import base64
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

class User():
    def __init__(self, keysize):
        res = lib.libprotector_User_new(ctypes.c_uint(keysize))
        self.user = res
    
    def setClientKey(self, user_key):
        return lib.libprotector_User_setUserKey(self.user, user_key)
    
    def setPrimeQ(self, prime_q):
        return lib.libprotector_User_setPrimeQ(self.user, prime_q)
    
    def setNumberG(self, number_g):
        return lib.libprotector_User_setNumberG(self.user, ctypes.c_char_p(number_g))
    
    def userTD(self, component):
        p1 = ctypes.c_char_p()
        p2 = ctypes.c_char_p()
        res = lib.libprotector_User_UserTD(self.user, ctypes.c_char_p(component), ctypes.c_uint(len(component)), ctypes.byref(p1), ctypes.byref(p2))
        return p1.value, p2.value
    
    def contentTD(self, block):
        p1 = ctypes.c_char_p()
        p2 = ctypes.c_char_p()
        res = lib.libprotector_User_ContentTD(self.user, ctypes.c_char_p(block), ctypes.c_uint(len(block)), ctypes.byref(p1), ctypes.byref(p2))
        return p1.value, p2.value
    
    def contentDec(self, block):
        p1 = ctypes.c_char_p()
        res = lib.libprotector_User_ClientDec(self.user, ctypes.c_char_p(block[0]), ctypes.c_char_p(block[1]), ctypes.byref(p1))
        return p1.value

class CCN():
    def __init__(self, keysize):
        res = lib.libprotector_CCN_new(ctypes.c_uint(keysize))
        self.ccn = res
    
    def setProxyKey(self, proxy_key):
        return lib.libprotector_CCN_setServerKey(self.ccn, proxy_key)
    
    def setPrimeQ(self, prime_q):
        return lib.libprotector_CCN_setPrimeQ(self.ccn, prime_q)
    
    def setNumberG(self, number_g):
        return lib.libprotector_CCN_setNumberG(self.ccn, number_g)
    
    def CCNTD(self, component):
        p1 = ctypes.c_char_p()
        
        res = lib.libprotector_CCN_CCNTD(self.ccn, ctypes.c_char_p(component[0]), ctypes.c_char_p(component[1]), ctypes.byref(p1))
        return p1.value
    
    def CCNContentTD(self, component):
        p1 = ctypes.c_char_p()
        p2 = ctypes.c_char_p()
        
        res = lib.libprotector_CCN_CCNContentTD(self.ccn, ctypes.c_char_p(component[0]), ctypes.c_char_p(component[1]), ctypes.byref(p1), ctypes.byref(p2))
        
        return p1.value, p2.value
    
    def CCNContentPreDec(self, component):
        p1 = ctypes.c_char_p()
        p2 = ctypes.c_char_p()
        
        res = lib.libprotector_CCN_CCNContentPreDec(self.ccn, ctypes.c_char_p(component[0]), ctypes.c_char_p(component[1]), ctypes.byref(p1), ctypes.byref(p2))
        
        return p1.value, p2.value

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

    KEYSIZE=1024
    
    for i in range(1):
        k = KMS()
        k.initKMS(KEYSIZE)
        k.addUser()
        proxy_key = k.getProxyKey(0)
        user_key  = k.getClientKey(0)
        prime_q = k.getPrimeQ()
        
        u = User(KEYSIZE)
        u.setClientKey(user_key)
        u.setPrimeQ(prime_q)
        u.setNumberG("2")
        user_td = u.userTD('hello')
        print "UserTD", user_td
        
        content_td = u.contentTD('A'*120)
        print "ContentTD", content_td
        
        #assert user_td == content_td #TODO: this should not happen when the pseudorandom function is applied.
        
        c = CCN(KEYSIZE)
        c.setProxyKey(proxy_key)
        c.setPrimeQ(prime_q)
        c.setNumberG("2")
        
        print "CCNTD", c.CCNTD(user_td)
        encr_content_td = c.CCNContentTD(content_td)
        print "CCNContentTD=", encr_content_td
        decr_content_td = c.CCNContentPreDec(encr_content_td)
        print decr_content_td
        
        print u.contentDec(decr_content_td)
        print u.contentDec(content_td)
