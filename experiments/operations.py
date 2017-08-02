import numpy
import optparse
import random
import time

import libprotector_interface

import lookup

def encrypt_and_decrypt(list_components, user_key, server_key, prime_q):
    res = [0,0,0,0]
    
    for c in list_components:
        
        start_time = time.time()
        u = libprotector_interface.user_enc_w_keys(c, user_key, prime_q)
        end_time = time.time()
        
        res[0] += end_time - start_time
        
        start_time = time.time()
        t = libprotector_interface.ccn_re_enc_w_keys(u, len(u), server_key, prime_q)
        end_time = time.time()
        
        res[1] += end_time - start_time
        
        start_time = time.time()
        t = str(libprotector_interface.ccn_pre_dec_w_keys(t, server_key, prime_q))
        end_time = time.time()
        
        res[2] += end_time - start_time
        
        start_time = time.time()
        libprotector_interface.client_dec_w_keys(t, user_key, prime_q)
        end_time = time.time()
        
        res[3] += end_time - start_time
    
    return res
        

def main(filename, number_names):
    data = lookup.readInput(filename)
    random.shuffle(data)
    
    selected_names = data[:number_names]
    del data
    
    res = []
    
    #get primeq, get userk, get server k
    user_key = libprotector_interface.getUserKey(0)
    server_key = libprotector_interface.getServerKey(0)
    prime_q = libprotector_interface.getPrimeQ()
    
    for name in selected_names:
        res.append(encrypt_and_decrypt(name, user_key, server_key, prime_q))
    
    return numpy.average(res, axis=0), numpy.std(res, axis=0)
    

if __name__ == '__main__':
    
    
    parser = optparse.OptionParser()
    parser.add_option("-t", "--trace_file",
                      dest="trace_filename",
                      default=None,
                      help="select the trace file")
    parser.add_option("-s", "--headers",
                      dest="show_headers",
                      help="Show headers.",
                      default=False,
                      action="store_true",
                      )
    parser.add_option("-x", "--number_names",
                      dest="number_names",
                      type=int,
                      help="number of names to evaluate"
    )
    (options, args) = parser.parse_args()
    
    r_a = []
    r_s = []

    r_a, r_s = main(options.trace_filename, options.number_names)
    
    if options.show_headers:
        print "user_enc_avg",
        print "\t",
        print "ccn_re_enc_avg",
        print "\t",
        print "ccn_pre_dec_avg",
        print "\t",
        print "client_dec_avg",
        print "\t",
        
        print "user_enc_std",
        print "\t",
        print "ccn_re_enc_std",
        print "\t",
        print "ccn_pre_dec_std",
        print "\t",
        print "client_dec_std"
    
    print "\t".join([str(x) for x in r_a]),
    print "\t",
    print "\t".join([str(x) for x in r_s]),
    print "\t"

