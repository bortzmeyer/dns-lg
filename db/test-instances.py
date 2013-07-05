#!/usr/bin/env python
# -*- coding: utf-8 -*-

# test-instances.py, Copyright (c) 2013, Jan-Piet Mens
# Test all instances of DNS-LG servers contained in YAML database.

import sys
import optparse
import yaml
import codecs
try:
    import json
except ImportError:
    import simplejson as json
import time
import urllib2
import socket

DBNAME = 'dns-lg.yaml'
timeout = 10

def loadf(filename):
    try:
        f = codecs.open(filename, 'r', 'utf-8')
        try:
            doc = yaml.load(f.read())
        except:
            print "Can't parse YAML in %s" % (filename)
            sys.exit(1)

        f.close()

        return doc

    except IOError, e:
        sys.stderr.write("Can't open file %s: %s\n" % (filename, e))
        sys.exit(1)

if __name__ == '__main__':

    p = optparse.OptionParser(
                usage='usage: %prog [options]',
                description='Test DNS-LG instances',
            )

    p.add_option("-f", "--database",
            action="store",
            dest="dbname",
            default=DBNAME,
            help="Path to YAML database")

    (options, args) = p.parse_args()

    sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    db = loadf(options.dbname)

    for lg in db:
        if 'endpoint' in lg:
            endpoint = lg['endpoint']

            uri = "%s/example.org/NS?format=json" % (endpoint)

            try:
                socket.setdefaulttimeout(timeout)
                req = urllib2.Request(uri)
                req.add_header("Accept", "application/json")
                req.add_header("User-Agent", "DNS Looking Glass Checker")

                resp = urllib2.urlopen(req)
                content = resp.read()
            except urllib2.HTTPError, e:
                print "Can't connect to %s: %s" % (endpoint, str(e))
                continue
            except urllib2.URLError, e:
                print "Can't connect to %s: %s" % (endpoint, str(e))
                continue
            except socket.timeout:
                print "Can't connect to %s: timeout" % (endpoint)
                continue
            print endpoint
            try:
                reply = json.loads(content)
            except ValueError:
                print "\tCannot decode JSON: %s" % content
                continue
            except:
                raise

            if 'AnswerSection' in reply:
                for ans in reply['AnswerSection']:
                    print "\t%s  %s  %s" % (ans['Name'], ans['Type'], ans['Target'])

