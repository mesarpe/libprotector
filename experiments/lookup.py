"""
    Script used for evaluating the speed of lookups with and without PROTECTOR.
"""
import numpy
import optparse
import random
import time

import libprotector_interface

def callProtector(component):
    a = libprotector_interface.user_enc(component)
    res = str(a)
    len_ = len(res)
    return libprotector_interface.ccn_re_enc(a, len(a))

def compareTwoNames(n1, n2):
    res = True
    
    i=0
    while i<min(len(n1), len(n2)):
        n1[i] == n2[i]
        i+=1


def readInput(filename):
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

def encrypt(list_components, use_protector=False):
    new_l = []
    for name in list_components:
        p = []
        for c in name:
            p.append(str(callProtector(c)))
        new_l.append(p)
    return new_l

def splitInput(data, percentage):
    assert 0 <= percentage and percentage <= 1
    len_ = len(data)
    
    return data[:int(len_*percentage)], data[int(len_*percentage):]

def main(filename, protector):

    data = readInput(filename)
    assert len(data) > 0
    random.shuffle(data)
    userset, _ = splitInput (data, 0.1)
    routerset = data
    
    if protector:
        userset = encrypt(userset, protector)
        routerset = encrypt(routerset, protector)
    
    start_time = time.time()
    
    for u in userset:
        for r in userset:
            compareTwoNames(u, r)
            
    
    end_time = time.time()
    
    return end_time - start_time


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
    parser.add_option("-s", "--headers",
                      dest="show_headers",
                      help="Show headers.",
                      default=False,
                      action="store_true",
                      )
    (options, args) = parser.parse_args()
    
    r = []
    for i in range(0, options.repetitions):
        r.append(main(options.trace_filename, options.protector))
    
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
