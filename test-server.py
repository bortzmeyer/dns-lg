#!/usr/bin/env python

import wsgiref.simple_server as server
import os
import getopt
import sys
import DNSLG

# This server receives parameters from hardcoded values or from the
# command line. The other, test-server-with-config-file.py, receives
# them from a configuration file.
port = 8080
email_admin = "foobar@invalid"
url_doc = None
url_css = None

def usage(msg=None):
    print >>sys.stderr, "Usage: %s [-p PORT] [-a email-admin] [-d url-documentation] [-c url-css]" % sys.argv[0]
    if msg is not None:
        print >>sys.stderr, msg

try:
    optlist, args = getopt.getopt (sys.argv[1:], "c:d:a:p:h",
                               ["documentation=", "css=", "admin=", "port=", "help"])
    for option, value in optlist:
        if option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        elif option == "--port" or option == "-p":
            port = int(value) # TODO: handle the possible conversion exception
            # to provide a better error message?
        elif option == "--admin" or option == "-a":
            # TODO: test the syntax
            email_admin = value
        elif option == "--css" or option == "-c":
            url_css = value
        elif option == "--documentation" or option == "-d":
            url_doc = value
        else:
            # Should never occur, it is trapped by getopt
            print >>sys.stderr, "Unknown option %s" % option
            usage()
            sys.exit(1)
except getopt.error, reason:
    usage(reason)
    sys.exit(1)
if len(args) != 0:
    usage()
    sys.exit(1)

querier = DNSLG.Querier(email_admin, url_doc, url_css)
# TODO listen on IPv6 as well
httpd = server.make_server("", port, querier.application)
print "Serving HTTP on port %i..." % port

# Respond to requests until process is killed
httpd.serve_forever()

