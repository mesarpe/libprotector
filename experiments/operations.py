import logging
import numpy
import optparse
import random
import time

import libprotector_interface

import lookup

NR_USERS = 0

def encrypt_and_decrypt(list_components, k, keysize):
    global NR_USERS
    res = [0,0,0,0,0,0,0,0]
    
    #get primeq, get userk, get server k
    
    
    start_time = time.time()
    k.addUser()
    end_time = time.time()
    res[7] += end_time - start_time
    
    
    server_key = k.getProxyKey(NR_USERS)
    user_key = k.getClientKey(NR_USERS)
    prime_q = k.getPrimeQ()
    NR_USERS+=1
    
    for c in list_components:
        content = "A"*2048
    
        logging.debug("Component={0}".format(c))
        logging.debug("Content={0}".format(content))
        
        start_time = time.time()
        u = libprotector_interface.user_enc_w_keys(c, user_key, prime_q)
        end_time = time.time()
        
        logging.debug("NameTD={0}".format(u))
        
        res[0] += end_time - start_time
        
        start_time = time.time()
        t = libprotector_interface.ccn_re_enc_w_keys(u, len(u), server_key, prime_q)
        end_time = time.time()
        
        res[1] += end_time - start_time
        
        logging.debug("CCN-NameTD={0}".format(t))
        
        start_time = time.time()
        content = libprotector_interface.user_enc_w_keys(content, user_key, prime_q)
        end_time = time.time()
        
        res[2] += end_time - start_time
        
        logging.debug("ContentTD={0}".format(content))
        
        start_time = time.time()
        content_mk = libprotector_interface.ccn_re_enc_w_keys(content, len(content), user_key, prime_q)
        end_time = time.time()
        
        res[3] += end_time - start_time
        
        logging.debug("CCN-ContentTD={0}".format(content_mk))
        
        start_time = time.time()
        t = str(libprotector_interface.ccn_pre_dec_w_keys(content_mk, server_key, prime_q))
        end_time = time.time()
        
        res[4] += end_time - start_time
        
        logging.debug("CCN-Content-Dec={0}".format(t))
        
        start_time = time.time()
        t = libprotector_interface.client_dec_w_keys(t, user_key, prime_q)
        end_time = time.time()
        
        res[5] += end_time - start_time
        
        logging.debug("Content-Dec={0}".format(t))
    
    return res
        

def main(filename, keysize, number_names, debug=False):
    data = lookup.readInput(filename)
    random.shuffle(data)
    
    selected_names = data[:number_names]
    del data
    
    res = []
    
    
    for name in selected_names:
        k = libprotector_interface.KMS()
        k.initKMS(keysize)
        res.append(encrypt_and_decrypt(name, k, keysize))
    
    return numpy.average(res, axis=0), numpy.std(res, axis=0)
    

if __name__ == '__main__':
    
    
    parser = optparse.OptionParser()
    parser.add_option("-t", "--trace_file",
                      dest="trace_filename",
                      default=None,
                      help="select the trace file")
    parser.add_option("-x", "--number_names",
                      dest="number_names",
                      type=int,
                      help="number of names to evaluate"
    )
    parser.add_option("-k", "--keysize",
                      dest="keysize",
                      type=int,
                      help="security parameter, keysize"
    )
    parser.add_option("-d", "--debug",
                      dest="debug",
                      default=False,
                      action="store_true",
                      help=""
    )
    (options, args) = parser.parse_args()
    
    if options.debug:
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
    
    r_a = []
    r_s = []

    r_a, r_s = main(options.trace_filename, options.keysize, options.number_names)
    
    functions = ["user_enc", "ccn_re_enc", "cp_enc", "cp_re_enc", "ccn_pre_dec", "client_dec", "initKMS", "keygen"]
    
    for i in range(len(r_a)):
        print functions[i], r_a[i], r_s[i]    
    #print "\t".join([str(x) for x in r_a]),
    #print "\t",
    #print "\t".join([str(x) for x in r_s]),
    
