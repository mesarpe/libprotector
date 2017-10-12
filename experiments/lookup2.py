"""
    Script used for evaluating the speed of lookups with and without PROTECTOR.
"""
import numpy
import optparse
import random
import time
import sys

from libprotector_interface import KMS, User, CCN

class Structure(object):
    def __init__(self):
        self.dict = {}
        self.time = []
        
    def consume_name(self, name):
        
        for i in range(len(name), 0, -1):
            lookup_name = name[0:i]
            self.dict["/".join(lookup_name)] = "/".join(name)
    
    def lookup(self, name):
        start_time = time.time()
        res = None, None
    
        for i in range(len(name), 0, -1):
            lookup_name = "/".join(name[0:i])
            if self.dict.has_key(lookup_name):
                res = lookup_name, self.dict[lookup_name]
                break

        end_time = time.time()
        self.time.append(end_time - start_time)
        return res
    
    def count_table_size(self):
        res = 0
        for k in self.dict.keys():
            res += len(k)
        
        return res
    
    def get_result(self):
        table_size = self.count_table_size()
        if self.time != []:
            return numpy.average(self.time), sys.getsizeof(self.dict), table_size
        else:
            return 0, sys.getsizeof(self.dict), table_size

class Experiment(object):
    def __init__(self, filename, keysize, table_limit, protector=False):
        self.protector = protector
        
        self.table_limit = table_limit
        
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
        
        self.list_of_names(filename)
    
    def process_name(self, component):
        if self.protector:
            return self.ccn.CCNTD(self.user.userTD(component))
        return component
    
    def list_of_names(self, filename):
        self.list_names =  [n for n in file(options.trace_filename).read().split('\n') if n != '']
        self.list_names = [[self.process_name(c) for c in name.split('/')] for name in self.list_names]
        random.shuffle(self.list_names)
        self.lookup_names = self.list_names[:100]
        random.shuffle(self.list_names)
        self.table_names = self.list_names[:self.table_limit]
    
    def run(self):
        s = Structure()
        for name in self.table_names:
            s.consume_name(name)
        
        assert self.table_names != self.lookup_names    
        
        res = [0,0]
        for name in self.lookup_names:
            a, b = s.lookup(name)
            res[0] += int(a == None)
            res[1] += int(b == None)
        
        return s.get_result()
    

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
    parser.add_option("-r", "--repetitions",
                      dest="repetitions",
                      default=1,
                      type=int,
                      help="number of repetitions of the experiment"
                    )
    parser.add_option("-k", "--keysize",
                      dest="keysize",
                      type=int,
                      help="security parameter, keysize"
    )
    parser.add_option("-x", "--number_names",
                      dest="number_names",
                      default=0,
                      type=int,
                      help="number of names to evaluate"
    )
    
    """parser.add_option("-s", "--headers",
                      dest="show_headers",
                      help="Show headers.",
                      default=False,
                      action="store_true",
                      )
    """
    
    (options, args) = parser.parse_args()
        
    e = Experiment(options.trace_filename, options.keysize, options.number_names, options.protector)
    
    results = []
    for r in range(0, options.repetitions):
        results.append(list(e.run()))
    
    results = numpy.array(results)
    results_a = numpy.average(results, axis=0)
    results_s = numpy.std(results, axis=0)
    metrics = ['match_time', 'python_table_size', 'total_sum_length_names(string_length)']
    
    for i in range(len(results_a)):
        print metrics[i], results_a[i], results_s[i]
    
