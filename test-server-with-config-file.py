#!/usr/bin/env python

import wsgiref.simple_server as server
import os
import getopt
import sys
import ConfigParser

config_file = os.path.expanduser("~/.dnslg.ini")

import DNSLG

default_values = {'email_administrator': None,
                  'url_documentation': None,
                  'url_css': None,
                  'url_base_service': DNSLG.default_base_url,
                  'file_favicon': None,
                  'encoding': DNSLG.default_encoding,
                  'size_edns': '2048',
                  'bucket_size': '10',
                  'handle_wellknown_files': 'True',
                  'code_google_webmasters': None,
                  'description': None,
                  'description_html': None,
                  'port': '8080'
                  }

def usage(msg=None):
    print >>sys.stderr, "Usage: %s" % sys.argv[0]
    if msg is not None:
        print >>sys.stderr, msg

if len(sys.argv) != 1:
    usage()
    sys.exit(1)

SECTION = "DNS-LG"
config = ConfigParser.SafeConfigParser(default_values)
try:
    config_file = open(config_file)
except IOError:
    print >>sys.stderr, "Cannot open configuration file %s" % config_file
    sys.exit(1)
config.readfp(config_file)
if not config.has_section(SECTION):
    config.add_section(SECTION)
email_admin = config.get(SECTION, 'email_administrator')
url_doc = config.get(SECTION, 'url_documentation')
url_css = config.get(SECTION, 'url_css')
file_favicon = config.get(SECTION, 'file_favicon')
base_url = config.get(SECTION, 'url_base_service')
port = config.getint(SECTION, 'port')
rl_bucket_size = config.getint(SECTION, 'bucket_size')
handle_wellknown_files = config.getboolean(SECTION, 'handle_wellknown_files')
description = config.get(SECTION, 'description')
description_html = config.get(SECTION, 'description_html')
google_code = config.get(SECTION, 'code_google_webmasters')
edns_size = config.get(SECTION, 'size_edns')
if edns_size is None or edns_size == "":
    edns_size = None
else:
    edns_size = int(edns_size) # TODO: handle conversion errors
encoding = config.get(SECTION, 'encoding')

querier = DNSLG.Querier(email_admin=email_admin, url_doc=url_doc, url_css=url_css,
                        base_url=base_url, file_favicon=file_favicon,
                        encoding=encoding,
                        edns_size=edns_size, bucket_size=rl_bucket_size,
                        google_code=google_code,
                        handle_wk_files=handle_wellknown_files,
                        description=description, description_html=description_html)
# TODO listen on IPv6 as well
httpd = server.make_server("", port, querier.application)
print "Serving HTTP on port %i..." % port

# Respond to requests until process is killed
httpd.serve_forever()

