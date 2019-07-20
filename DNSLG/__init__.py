#!/usr/bin/env python

# Standard library
from cgi import escape
from urlparse import parse_qs
import encodings.idna
import os
from datetime import datetime

# http://www.dnspython.org/
import dns.resolver
import dns.reversename

# http://code.google.com/p/netaddr/ https://github.com/drkjam/netaddr
import netaddr

# http://webob.org/
# Debian package python-webob
from webob import Request

# Internal modules
import Formatter
from LeakyBucket import LeakyBucket
import Answer
import Resolver

# If you need to change thse values, it is better to do it when
# calling the Querier() constructor.
default_base_url = "" 
default_edns_size = 4096
# TODO: allow to use prefixes in the whitelist
default_whitelist=[netaddr.IPAddress("127.0.0.1"), netaddr.IPAddress("::1")]
default_encoding = "UTF-8"
default_handle_wk_files = True
default_bucket_size = 5

# Misc. util. routines
def send_response(start_response, status, output, type):
    # TODO: an input parameter indicating the expiration time, and
    # produces an Expires: HTTP header. See issue #13
    response_headers = [('Content-type', type),
                        ('Content-Length', str(len(output))),
                        ('Allow', 'GET'),
                        ('Link', '<https://www.bortzmeyer.org/dns-lg-usage.html>; rel="service-doc"; type="text/html"']
    start_response(status, response_headers)

def punycode_of(domain):
    labels = domain.split(".")
    result = u""
    for label in labels:
        if label:
            result += (encodings.idna.ToASCII(label) + ".")
    return (result)

class Querier:

    def __init__(self, email_admin=None, url_doc=None, url_css=None, url_opensearch=None,
                 file_favicon=None,
                 encoding=default_encoding, base_url=default_base_url,
                 bucket_size=default_bucket_size,
                 whitelist=default_whitelist, edns_size=default_edns_size,
                 handle_wk_files=default_handle_wk_files,
                 google_code=None, description=None, description_html=None, 
                 forbidden_suffixes=[]):
        self.resolver = Resolver.Resolver(edns_payload=edns_size)
        self.buckets = {}
        self.base_url = base_url
        self.whitelist = whitelist
        self.handle_wk_files = handle_wk_files
        self.email_admin = email_admin
        self.url_doc = url_doc
        self.url_css = url_css
        self.url_opensearch = url_opensearch
        if file_favicon:
            self.favicon = open(file_favicon).read()
        else:
            self.favicon = None
        self.encoding = encoding
        self.bucket_size = default_bucket_size
        self.google_code = google_code
        self.description = description
        self.description_html = description_html
        self.forbidden_suffixes = []
        for suffix in forbidden_suffixes:
            if suffix != '':
                if not suffix.endswith('.'):
                    suffix += '.'
                self.forbidden_suffixes.append(suffix)
        self.resolver.reset()
        
    def default(self, start_response, path):
        output = """
I'm the default handler, \"%s\" was called.
Are you sure of the URL?\n""" % path
        send_response(start_response, '404 No such resource' , output, 'text/plain; charset=%s' % self.encoding)
        return [output]

    def emptyfile(self, start_response):
        output = ""        
        send_response(start_response, '200 OK' , output, 'text/plain')
        return [output]

    def robotstxt(self, start_response):
        # http://www.robotstxt.org/
        # TODO: allow to read it in the configuration file
        output = """
User-agent: *
Disallow: /
"""        
        send_response(start_response, '200 OK' , output, 'text/plain')
        return [output]

    def notfound(self, start_response):
        output = "Not found\r\n"        
        send_response(start_response, '404 Not Found' , output, 'text/plain')
        return [output]

    def query(self, start_response, req, path, client, format="", alt_resolver=None,
              do_dnssec=False, tcp=False, cd=False, edns_size=default_edns_size,
              reverse=False):
        """ path must starts with a /, then the domain name then an
        (optional) / followed by the QTYPE """
        if not path.startswith('/'):
            raise Exception("Internal error: no / at the beginning of %s" % path)
        plaintype = 'text/plain; charset=%s' % self.encoding
        if not format:
            mformat = req.accept.best_match(['text/html', 'application/xml',
                                            'application/json', 'text/dns',
                                            'text/plain'])
            if mformat == "text/html":
                format = "HTML"
            elif mformat == "application/xml":
                format = "XML"
            elif mformat == "application/json":
                format = "JSON"
            elif mformat == "text/dns":
                format = "ZONE"
            elif mformat == "text/plain":
                format = "TEXT"    
            if not mformat:
                output = "No suitable output format found\n" 
                send_response(start_response, '400 Bad request', output, plaintype)
                return [output]
            mtype = '%s; charset=%s' % (mformat, self.encoding)
        else:
            if format == "TEXT" or format == "TXT":
                format = "TEXT"
                mtype = 'text/plain; charset=%s' % self.encoding
            elif format == "HTML":
                mtype = 'text/html; charset=%s' % self.encoding
            elif format == "JSON":
                mtype = 'application/json'
            elif format == "ZONE":
                mtype = 'text/dns' # RFC 4027
            # TODO: application/dns, "detached" DNS (binary), see issue #20
            elif format == "XML":
                mtype = 'application/xml'
            else:
                output = "Unsupported format \"%s\"\n" % format
                send_response(start_response, '400 Bad request', output, plaintype)
                return [output]
        ip_client = netaddr.IPAddress(client)
        if ip_client.version == 4:
            ip_prefix = netaddr.IPNetwork(client + "/28")
        elif ip_client.version == 6:
            ip_prefix = netaddr.IPNetwork(client + "/64")
        else:
            output = "Unsupported address family \"%s\"\n" % ip_client.version
            send_response(start_response, '400 Unknown IP version', output, plaintype)
            return [output]
        if ip_client not in self.whitelist:
            if self.buckets.has_key(ip_prefix.cidr):
                if self.buckets[ip_prefix.cidr].full():
                    status = '429 Too many requests'
                    # 429 registered by RFC 6585 in april 2012
                    # http://www.iana.org/assignments/http-status-codes
                    # Already common
                    # http://www.flickr.com/photos/girliemac/6509400997/in/set-72157628409467125
                    output = "%s sent too many requests" % client # TODO: better message
                    send_response(start_response, status, output, plaintype)
                    return [output]
                else:
                    self.buckets[ip_prefix.cidr].add(1)
            else:
                self.buckets[ip_prefix.cidr] = LeakyBucket(size=self.bucket_size)
        args = path[1:]
        slashpos = args.find('/')
        if slashpos == -1:
            if reverse:
                domain = str(dns.reversename.from_address(args))
                qtype = 'PTR'
            else:
                domain = args
                qtype = 'ADDR'
            qclass = 'IN'
        else:
            if reverse:
                domain = str(dns.reversename.from_address(args[:slashpos]))
            else:
                domain = args[:slashpos]
            nextslashpos = args.find('/', slashpos+1)
            if nextslashpos == -1:
                requested_qtype = args[slashpos+1:].upper()
                qclass = 'IN'
            else:
                requested_qtype = args[slashpos+1:nextslashpos].upper()
                qclass = args[nextslashpos+1:].upper()
            # We do not test if the QTYPE exists. If it doesn't
            # dnspython will raise an exception. The formatter will
            # have to deal with the various records.
            if requested_qtype == "":
                if reverse:
                    qtype = 'PTR'
                else:
                    qtype = 'ADDR'
            else:
                qtype = requested_qtype
            if reverse and qtype != 'PTR':
                output = "You cannot ask for a query type other than PTR with reverse queries\n" 
                send_response(start_response, '400 Bad qtype with reverse',
                              output, plaintype)
                return [output]
            # Pseudo-qtype ADDR is handled specially later
        if not domain.endswith('.'):
            domain += '.'
        if domain == 'root.':
            domain = '.'
        domain = unicode(domain, self.encoding)
        for forbidden in self.forbidden_suffixes:
            if domain.endswith(forbidden):
                output = "You cannot query local domain %s" % forbidden
                send_response(start_response, '403 Local domain is private',
                              output, plaintype)
                return [output]
        punycode_domain = punycode_of(domain)
        if punycode_domain != domain:
            qdomain = punycode_domain.encode("US-ASCII")
        else:
            qdomain = domain.encode("US-ASCII")
        try:
            if format == "HTML":
                formatter = Formatter.HtmlFormatter(domain)
            elif format == "TEXT":
                formatter = Formatter.TextFormatter(domain)
            elif format == "JSON":
                formatter = Formatter.JsonFormatter(domain)
            elif format == "ZONE":
                formatter = Formatter.ZoneFormatter(domain)
            elif format == "XML":
                formatter = Formatter.XmlFormatter(domain)
            self.resolver.reset()
            if edns_size is None:
                self.resolver.set_edns(version=-1)
            else:
                if do_dnssec:
                    self.resolver.set_edns(payload=edns_size, dnssec=True)
                else:
                    self.resolver.set_edns(payload=edns_size)
            if alt_resolver:
                self.resolver.set_nameservers([alt_resolver,])
            query_start = datetime.now()
            if qtype != "ADDR":
                answer = self.resolver.query(qdomain, qtype, qclass, tcp=tcp, cd=cd)
            else:
                try:
                    answer = self.resolver.query(qdomain, "A", tcp=tcp, cd=cd)
                except dns.resolver.NoAnswer: 
                    answer = None
                try:
                    answer_bis = self.resolver.query(qdomain, "AAAA", tcp=tcp, cd=cd)
                    if answer_bis is not None:
                        for rrset in answer_bis.answer:
                            answer.answer.append(rrset)
                except dns.resolver.NoAnswer: 
                    pass  
                # TODO: what if flags are different with A and AAAA? (Should not happen)
                if answer is None:
                    query_end = datetime.now()
                    self.delay = query_end - query_start
                    formatter.format(None, qtype, qclass, 0, self)
                    output = formatter.result(self)
                    send_response(start_response, '200 OK', output, mtype)
                    return [output]
            query_end = datetime.now()
            self.delay = query_end - query_start
            formatter.format(answer, qtype, qclass, answer.flags, self)
            output = formatter.result(self)
            send_response(start_response, '200 OK', output, mtype)
        except Resolver.UnknownRRtype:
            output = "Record type %s does not exist\n" % qtype
            output = output.encode(self.encoding)
            send_response(start_response, '400 Unknown record type', output, 
                          plaintype)
        except Resolver.UnknownClass:
            output = "Class %s does not exist\n" % qclass
            output = output.encode(self.encoding)
            send_response(start_response, '400 Unknown class', output, 
                          plaintype)
        except Resolver.NoSuchDomainName:
            output = "Domain %s does not exist\n" % domain
            output = output.encode(self.encoding)
            # TODO send back in the requested format (see issue #11)
            send_response(start_response, '404 No such domain', output, plaintype)
        except Resolver.Refused:
            output = "Refusal to answer for all name servers for %s\n" % domain
            output = output.encode(self.encoding)
            send_response(start_response, '403 Refused', output, plaintype)
        except Resolver.Servfail:
            output = "Server failure for all name servers for %s (may be a DNSSEC validation error)\n" % domain
            output = output.encode(self.encoding)
            send_response(start_response, '504 Servfail', output, plaintype)
        except Resolver.Timeout: 
            output = "No server replies for domain %s\n" % domain
            output = output.encode(self.encoding)
            # TODO issue #11. In that case, do not serialize output.
            send_response(start_response, '504 Timeout', output,
                          "text/plain")
        except Resolver.NoPositiveAnswer: 
            output = "No server replies for domain %s\n" % domain
            output = output.encode(self.encoding)
            # TODO issue #11
            send_response(start_response, '504 No positive answer', output,
                          "text/plain")
        except Resolver.UnknownError as code:
            output = "Unknown error %s resolving %s\n" % (dns.rcode.to_text(int(str(code))), domain)
            output = output.encode(self.encoding)
            # TODO issue #11
            send_response(start_response, '500 Unknown server error', output, plaintype)
        return [output]
    
    def application(self, environ, start_response):
        plaintype = 'text/plain; charset=%s' % self.encoding
        # TODO see issue #1 about HEAD support
        if environ['REQUEST_METHOD'] != 'GET':
            output = environ['REQUEST_METHOD']
            send_response(start_response, '405 Method not allowed', output, plaintype)
            return [output]
        # If the program runs under Apache and if you use Apache
        # SetEnv directives, their values can be retrieved here inside
        # dictionary "environ".
        path = environ['PATH_INFO']
        queries = parse_qs(environ['QUERY_STRING'])
        client = environ['REMOTE_ADDR']
        if path.startswith(self.base_url):
            # TODO: find a way to find unknown options and croak on them
            resolver = None
            resolver = queries.get("server", [''])[0]
            format = queries.get("format", [''])[0].upper()
            dodnssec = queries.get("dodnssec", '')
            do_dnssec = not(len(dodnssec) == 0 or dodnssec[0] == "0" or \
                            dodnssec[0].lower() == "false" or dodnssec[0] == "")
            dotcp = queries.get("tcp", '')
            tcp = not(len(dotcp) == 0 or dotcp[0] == "0" or \
                            dotcp[0].lower() == "false" or dotcp[0] == "")

            docd = queries.get("cd", '')
            cd = not(len(docd) == 0 or docd[0] == "0" or \
                            docd[0].lower() == "false" or docd[0] == "")
            doreverse = queries.get("reverse", '')
            reverse = not(len(doreverse) == 0 or doreverse[0] == "0" or \
                            doreverse[0].lower() == "false" or doreverse[0] == "")
            buffersize = int(queries.get("buffersize", [default_edns_size])[0])
            if cd:
                if not do_dnssec:
                    output = "Incompatible arguments"
                    send_response(start_response, '400 CD is meaningful only for DNSSEC',
                                  output, plaintype)
                    return [output]
            if buffersize == 0:
                if do_dnssec:
                    output = "Buffer size = 0"
                    send_response(start_response, '400 DNSSEC requires EDNS',
                                  output, plaintype)
                    return [output]
                edns_size = None
            else:
                edns_size = buffersize
            if self.base_url == '' and self.handle_wk_files:
                # Handle the special cases: home page, robots.txt,
                # favicon.ico, .well-known, Google
                # Webmasters cookie files...
                if path == "/robots.txt":
                    return self.robotstxt(start_response)
                elif path == "/favicon.ico":
                    if self.base_url == '' and self.favicon:
                        output = self.favicon
                        send_response(start_response, '200 OK' , output, 'image/x-icon')
                        return [output]
                    else:
                        return self.notfound(start_response)
                elif path.startswith("/.well-known"): # RFC 5785
                    return self.notfound(start_response)
                elif self.google_code and (path == "/%s.html" % self.google_code):
                    return self.emptyfile(start_response)
                # Another solution, for Apache, it to use the Alias
                # directive, 'Alias /robots.txt
                # /usr/local/www/documents/robots.txt" etc.
            pure_path = path[len(self.base_url):]
            return self.query(start_response, Request(environ), pure_path, client, format, resolver,
                              do_dnssec, tcp, cd, edns_size, reverse)
        else:
            return self.default(start_response, path)

