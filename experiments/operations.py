import base64
import logging
import numpy
import optparse
import random
import time

import libprotector_interface

from libprotector_interface import KMS, CCN, User

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
    
    proxy_key = k.getProxyKey(0)
    user_key  = k.getClientKey(0)
    prime_q = k.getPrimeQ()
    
    user = User(keysize)
    user.setClientKey(user_key)
    user.setPrimeQ(prime_q)
    user.setNumberG("2")
    
    ccn = CCN(keysize)
    ccn.setProxyKey(proxy_key)
    ccn.setPrimeQ(prime_q)
    ccn.setNumberG("2")
    
    
    
    
    
    server_key = k.getProxyKey(NR_USERS)
    user_key = k.getClientKey(NR_USERS)
    prime_q = k.getPrimeQ()
    NR_USERS+=1
    
    original_content = base64.b64encode("A"*20)
    logging.debug("Content={0}".format(original_content))
    
    for c in list_components:
        
    
        logging.debug("Component={0}".format(c))
        
        start_time = time.time()
        u = user.userTD(c)
        end_time = time.time()
        
        logging.debug("NameTD={0}".format(u))
        
        res[0] += end_time - start_time
        
        start_time = time.time()
        t = ccn.CCNTD(u)
        end_time = time.time()
        
        res[1] += end_time - start_time
        
        logging.debug("CCN-NameTD={0}".format(t))
        
    start_time = time.time()
    content = user.contentTD(original_content)
    end_time = time.time()
    
    res[2] += end_time - start_time
    
    logging.debug("ContentTD={0}".format(content))
    
    start_time = time.time()
    content_mk = ccn.CCNContentTD(content)
    end_time = time.time()
    
    res[3] += end_time - start_time
    
    logging.debug("CCN-ContentTD={0}".format(content_mk))
    
    start_time = time.time()
    t = ccn.CCNContentPreDec(content_mk)
    end_time = time.time()
    
    res[4] += end_time - start_time
    
    logging.debug("CCN-Content-Dec={0}".format(t))
    
    start_time = time.time()
    t = user.contentDec(t)
    end_time = time.time()
    
    res[5] += end_time - start_time
    
    assert t == original_content
    
    logging.debug("Content-Dec={0}".format(t))
    
    return res
        

def main(filename, keysize, number_names, debug=False):
    data = lookup.readInput(filename)
    random.shuffle(data)
    
    selected_names = data[:number_names]
    del data
    
    res = []
    
    
    k = KMS()
    k.initKMS(keysize)
    for name in selected_names:
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
    
    functions = ["nameTD", "CCN-Name-TD", "ContentTD", "CCN-ContentTD", "CCN-Content-Pre-Dec", "Content-Dec", "initKMS", "keygen"]
    
    for i in range(len(r_a)):
        print functions[i], r_a[i], r_s[i]    
    #print "\t".join([str(x) for x in r_a]),
    #print "\t",
    #print "\t".join([str(x) for x in r_s]),
    
