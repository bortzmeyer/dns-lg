#!/usr/bin/env python

import ConfigParser
import sys
import string

import DNSLG

config_file_name = "/etc/dnslg.ini"

default_values = {'email_administrator': None,
                  'url_documentation': None,
                  'url_css': None,
                  'url_opensearch': None,
                  'file_favicon': None,
                  'url_base_service': DNSLG.default_base_url,
                  'encoding': DNSLG.default_encoding,
                  'size_edns': '2048',
                  'bucket_size': '5',
                  'handle_wellknown_files': 'True',
                  'code_google_webmasters': None,
                  'description': None,
                  'description_html': None,
                  'port': '8080' # Ignored for Apache
                  }

SECTION = "DNS-LG"
config = ConfigParser.SafeConfigParser(default_values)
try:
    config_file = open(config_file_name)
except IOError:
    print >>sys.stderr, "Cannot open configuration file %s" % config_file_name
    sys.exit(1)
config.readfp(config_file)
config.set('DEFAULT', 'forbidden_suffixes', '')
if not config.has_section(SECTION):
    config.add_section(SECTION)
email_admin = config.get(SECTION, 'email_administrator')
url_doc = config.get(SECTION, 'url_documentation')
url_css = config.get(SECTION, 'url_css')
url_opensearch = config.get(SECTION, 'url_opensearch')
file_favicon = config.get(SECTION, 'favicon')
base_url = config.get(SECTION, 'url_base_service')
port = config.getint(SECTION, 'port')
rl_bucket_size = config.getint(SECTION, 'bucket_size')
handle_wellknown_files = config.getboolean(SECTION, 'handle_wellknown_files')
description = config.get(SECTION, 'description')
description_html = config.get(SECTION, 'description_html')
google_code = config.get(SECTION, 'code_google_webmasters')
edns_size = config.get(SECTION, 'size_edns')
forbidden_str = config.get(SECTION, 'forbidden_suffixes')
forbidden = string.split(forbidden_str, ':')
if edns_size is None or edns_size == "":
    edns_size = None
else:
    edns_size = int(edns_size) # TODO: handle conversion errors
encoding = config.get(SECTION, 'encoding')

querier = DNSLG.Querier(email_admin=email_admin, url_doc=url_doc, url_css=url_css,
                        url_opensearch=url_opensearch, file_favicon=file_favicon,
                        base_url=base_url, encoding=encoding,
                        edns_size=edns_size, bucket_size=rl_bucket_size,
                        google_code=google_code,
                        handle_wk_files=handle_wellknown_files,
                        description=description, description_html=description_html,
                        forbidden_suffixes=forbidden)

application = querier.application
