#!/usr/bin/python

import DNSLG
import sys

resolver = DNSLG.Resolver.Resolver(["127.0.0.1", "8.8.8.8"], maximum=2)
for name in sys.argv[1:]:
    result = resolver.query(name, "ANY")
    print result.answer
    print "From %s: " % result.nameserver
    rrsets = result.answer # There is also additional, authority, etc
    for rrset in rrsets:
        print "%s/%s ->" % (rrset.name, rrset.rdtype)
        for rr in rrset:
            print "\t%s" % rr
    print ""
