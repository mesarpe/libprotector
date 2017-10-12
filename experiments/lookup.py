"""
    Script used for evaluating the speed of lookups with and without PROTECTOR.
"""
import numpy
import optparse
import random
import time
import logging

from libprotector_interface import KMS, User, CCN

class Experiment(object):
    def __init__(self, keysize):
        KEYSIZE=keysize
    
        self.kms = KMS()
        self.kms.initKMS(KEYSIZE)
        self.kms.addUser()
        proxy_key = self.kms.getProxyKey(0)
        user_key  = self.kms.getClientKey(0)
        prime_q = self.kms.getPrimeQ()
        
        self.user = User(KEYSIZE)
        self.user.setClientKey(user_key)
        self.user.setPrimeQ(prime_q)
        self.user.setNumberG("2")
        
        self.ccn = CCN(KEYSIZE)
        self.ccn.setProxyKey(proxy_key)
        self.ccn.setPrimeQ(prime_q)
        self.ccn.setNumberG("2")
        

    def callProtector(self, component):
        #a = libprotector_interface.user_enc_w_keys(component, user_key, prime_q)
        #res = str(a)
        #len_ = len(res)
        #return libprotector_interface.ccn_re_enc_w_keys(a, len(a), server_key, prime_q)
        return self.ccn.CCNTD(self.user.userTD(component))

    def compareTwoNames(self, n1, n2):
        res = True
        
        i=0
        l = []
        while i<min(len(n1), len(n2)):
            start_time = time.time()
            n1[i] == n2[i]
            end_time = time.time()
            l.append(end_time-start_time)
            i+=1
        
        if l == []:
            return 0
        else:
            return numpy.average(l)


    def readInput(self, filename):
        data = file(filename).read().split('\n')
        
        list_components = []
        for d in data:
            c = []
            components = d.split('/')
            for component in components:
                if component != '':
                    c.append(component)
            
            list_components.append(c)
        
        return list_components

    def encrypt(self, list_components, use_protector=False):

        new_l = []
        for name in list_components:
            p = []
            for c in name:
                p.append(str(self.callProtector(c)))
            new_l.append(p)
        return new_l

    def splitInput(self, data, percentage):
        assert 0 <= percentage and percentage <= 1
        len_ = len(data)
        
        return data[:int(len_*percentage)], data[int(len_*percentage):]

    def main(self, filename, protector):

        data = self.readInput(filename)
        assert len(data) > 0
        random.shuffle(data)
        userset, _ = self.splitInput (data, 0.1)
        routerset = data
        
        if protector:
            userset = self.encrypt(userset, protector)
            routerset = self.encrypt(routerset, protector)
        
        
        p = []
        for u in userset:
            for r in userset:
                res = self.compareTwoNames(u, r)
                if res > 0:
                    p.append(res)
        
        return numpy.average(p)


if __name__ == '__main__':
    
    
    parser = optparse.OptionParser()
    parser.add_option("-t", "--trace_file",
                      dest="trace_filename",
                      default=None,
                      help="select the trace file")
    parser.add_option("-p", "--protector-enabled",
                      dest="protector",
                      help="Specify that the libprotector will be used.",
                      default=False,
                      action="store_true",
                      )
    parser.add_option("-k", "--keysize",
                      dest="keysize",
                      type=int,
                      help="security parameter, keysize"
    )
    parser.add_option("-r", "--repetitions",
                      dest="repetitions",
                      default=1,
                      type=int,
                      help="number of repetitions of the experiment"
                    )
    parser.add_option("-s", "--headers",
                      dest="show_headers",
                      help="Show headers.",
                      default=False,
                      action="store_true",
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
    
    
    r = []
    e = Experiment(options.keysize)
    for i in range(0, options.repetitions):
        logging.debug('Iteration {0}'.format(i))
        r.append(e.main(options.trace_filename, options.protector))
    
    if options.show_headers:
        print "protector",
        print "\t",
        print "avg",
        print "\t",
        print "std",
        print "\t",
        print "repetitions"
    
    print "yes" if options.protector else "no",
    print "\t",
    print numpy.average(r),
    print "\t",
    print numpy.std(r),
    print "\t",
    print options.repetitions
