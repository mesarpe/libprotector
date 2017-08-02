#Interface for using libprotector
import ctypes
lib = ctypes.cdll.LoadLibrary('./../libprotector.so')

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
    res = lib.libprotector_ReEncryptUserContent(ctypes.c_char_p(t1), ctypes.c_uint(t2), ctypes.c_char_p(server_key), ctypes.c_char_p(prime_q))
    return ctypes.c_char_p(res).value 
def ccn_re_enc(t1, t2):
    return lib.libprotector_ReEncryptUserContent(ctypes.c_char_p(t1), ctypes.c_uint(t2))
    

def ccn_pre_dec_w_keys(t, server_key, prime_q):
    res = lib.libprotector_DecryptContent(ctypes.c_char_p(t), ctypes.c_char_p(server_key), ctypes.c_char_p(prime_q));
    
    return ctypes.c_char_p(res).value

def ccn_pre_dec(t):
    return lib.libprotector_DecryptContent(ctypes.c_char_p(t));

def client_dec_w_keys(t, user_key, prime_q):
    res = lib.libprotector_ReDecryptContent(ctypes.c_char_p(t), ctypes.c_char_p(user_key), ctypes.c_char_p(prime_q));
    
    return ctypes.c_char_p(res).value
def client_dec(t):
    return lib.libprotector_ReDecryptContent(ctypes.c_char_p(t));
