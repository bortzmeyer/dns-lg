#!/usr/bin/env python
# -*- coding: utf-8 -*-

# dbconv.py, Copyright (c) 2012, Jan-Piet Mens
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# converts DNS-LG YAML database to sundry (ahem!) formats

import sys
import optparse
import yaml
import codecs
try:
    import json
except ImportError:
    import simplejson as json
import time
HAVE_XML=True
try:
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
except ImportError:
    HAVE_XML=False

DBNAME = 'dns-lg.yaml'

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

def dns_txt(db, origin="dns-lg"):
    ''' Print in DNS master zone file format for inclusion into zone '''

    print "; Documentation of the existing DNS-LG instances."
    print ";"
    print "; Generated at %s" % (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()))
    print ";"
    print "; This file contains a TXT RRset for inclusion into a"
    print "; zone master file. Each endpoint is a TXT record."
    print ";"

    for ep in db:
        if 'endpoint' in ep and 'status' in ep and ep.get('status') != 'down':
            txt = "\"%s\"" % (ep['endpoint'])
            print "%-10s IN TXT  %-45s ; %s" % (origin, txt, ep.get('contact', ''))
            origin = ''   # on continuation line

def plain_txt(db):
    ''' Print database as plain text '''

    for ep in db:
        if 'endpoint' in ep:
            print "%-50s %s" % (ep['endpoint'], ep.get('contact', ''))

def prettyprint(elem):
    ''' Compliments of http://www.doughellmann.com/PyMOTW/xml/etree/ElementTree/create.html '''

    str = ET.tostring(elem, 'utf-8')
    newstr = minidom.parseString(str)

    return newstr.toprettyxml(indent="  ")

def xml_out(db):

    root = ET.Element('dns-lg')

    comment = ET.Comment('Generated at %s' % (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())))
    root.append(comment)
    

    for ep in db:
        if 'endpoint' in ep:
            child = ET.SubElement(root, 'endpoint')
            child.text = ep['endpoint']

            if 'contact' in ep:
                child.set('contact', ep.get('contact'))

            if 'status' in ep:
                child.set('status', ep.get('status'))

    print prettyprint(root)

if __name__ == '__main__':


    p = optparse.OptionParser(
                usage='usage: %prog [options]',
                description='Print DNS-LG database',
            )

    p.add_option("-f", "--database",
            action="store",
            dest="dbname",
            default=DBNAME,
            help="Path to YAML database")
    p.add_option("-j", "--json",
            action="store_true",
            default=False,
            dest='json',
            help='Output in JSON format')
    p.add_option("-o", "--origin",
            action="store",
            default="dns-lg",
            dest='origin',
            help='Specify origin for DNS zone master format. (default: dns-lg)')
    p.add_option("-t", "--text",
            action="store_true",
            default=True,
            dest='plain',
            help='Plain-text output')
    if HAVE_XML:
        p.add_option("-x", "--xml",
                action="store_true",
                default=False,
                dest='xml',
                help='XML format')
    p.add_option("-z", "--zone",
            action="store_true",
            default=False,
            dest='dnszone',
            help='master zone file format')

    (options, args) = p.parse_args()

    sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    db = loadf(options.dbname)

    if options.dnszone:
        dns_txt(db, options.origin)
    elif options.xml:
        xml_out(db)
    elif options.json:
        print json.dumps(db, indent=4)
    else: 
        plain_txt(db)

