import logging
import numpy
import optparse
import random
import time

from libprotector_interface import KMS, CCN, User

class ComponentsExperiment(object):
    def __init__(self, filename, repetitions, keysize, nr_components):
        self.repetitions = repetitions
        self.keysize = keysize
        self.nr_components = nr_components
        
        k = KMS()
        k.initKMS(keysize)
        k.addUser()
        proxy_key = k.getProxyKey(0)
        user_key  = k.getClientKey(0)
        prime_q = k.getPrimeQ()
        
        self.user = User(keysize)
        self.user.setClientKey(user_key)
        self.user.setPrimeQ(prime_q)
        self.user.setNumberG("2")
        
        self.c = CCN(keysize)
        self.c.setProxyKey(proxy_key)
        self.c.setPrimeQ(prime_q)
        self.c.setNumberG("2")
        
        self.res = [0, 0]
        
        self.list_names = self.parse_file(filename)
    
    def parse_file(self, filename):
        data = file(filename).read().split('\n')
        
        l = []
        for d in data:
        
            components = d.split('/')
            for c in components:
                if c != '':
                    l.append(c)
        
        return l
    
    def run(self):
        for i in range(0, self.repetitions):
            n = self.generate_name(self.nr_components)
            self.test_name(n)
        self.res[0]/=self.repetitions
        self.res[1]/=self.repetitions

    def generate_name(self, nr_components, protector=False):
        return [random.choice(self.list_names) for i in range(0, nr_components)]
    
    def test_name(self, name):    
        
        for component in name:
            start_time = time.time()
            name_td = self.user.userTD(component)
            end_time = time.time()
            
            self.res[0] += end_time-start_time
            
            start_time = time.time()
            ccn_name_td = self.c.CCNTD(name_td)
            end_time = time.time()

            self.res[1] += end_time-start_time

    def get_results(self):
        return self.res

if __name__ == '__main__':
    
    
    parser = optparse.OptionParser()
    parser.add_option("-t", "--trace_file",
                      dest="trace_filename",
                      default=None,
                      help="select the trace file")
    parser.add_option("-r", "--repetitions",
                      dest="repetitions",
                      type=int,
                      help="number of times to repeat the experiment"
    )
    parser.add_option("-c", "--components",
                      dest="nr_components",
                      type=int,
                      help="number of components to evaluate"
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
        root = loaagging.getLogger()
        root.setLevel(logging.DEBUG)
    
    ce = ComponentsExperiment(options.trace_filename, options.repetitions, options.keysize, options.nr_components)
    ce.run()
    
    res = ce.get_results()
    
    print options.nr_components, res[0], res[1],
    
    #HOW TO RUN THIS EXPERIMENT:
    #for i in `seq 1 20`; do python components.py  --trace_file unibas-icn-names-2014-08-teaser.txt -r 1 -k 512 -c $i | xargs echo -n " "; python components.py  --trace_file unibas-icn-names-2014-08-teaser.txt -r 1 -k 1024 -c $i | xargs echo -n " "; echo -n " "; python components.py  --trace_file unibas-icn-names-2014-08-teaser.txt -r 1 -k 2048 -c $i; done
