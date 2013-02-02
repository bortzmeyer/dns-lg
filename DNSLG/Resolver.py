import copy

import dns.message
import dns.resolver
import Answer

DEFAULT_EDNS_SIZE=2048

class Timeout(Exception):
    pass

class NoSuchDomainName(Exception):
    pass

class NoNameservers(Exception):
    pass

class NoPositiveAnswer(Exception):
    pass

class Refused(Exception):
    pass

class Servfail(Exception):
    pass

class UnknownRRtype(Exception):
    pass

class UnknownClass(Exception):
    pass

class UnknownError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Resolver():
    
    def __init__(self, nameservers=None, maximum=3, timeout=1.0,
                 edns_version=0, edns_payload=DEFAULT_EDNS_SIZE, do_dnssec=False):
        # TODO: ednsflags such as NSID
        # TODO: the default timeout is too high for authoritative name
        # servers and too low for some far-away recursive: separate
        # the two cases?
        """ A "None" value for the parameter nameservers means to use
        the system's default resolver(s). Otherwise, this parameter
        is an *array* of the IP addresses of the resolvers.
        edns_version=0 means EDNS0, the original one. Use -1 for no EDNS """
        self.maximum = maximum
        self.timeout = timeout
        self.original_edns = edns_version
        self.original_payload = edns_payload
        self.original_do = do_dnssec
        if nameservers is None:
            self.original_nameservers = dns.resolver.get_default_resolver().nameservers
        else:
            # TODO: test it is an iterable? And of length > 0?
            self.original_nameservers = nameservers
        self.edns = self.original_edns
        self.payload = self.original_payload
        self.nameservers = self.original_nameservers
        self.do = self.original_do
        
    def query(self, name, type, klass='IN', tcp=False, cd=False):
        """ The returned value is a DNSLG.Answer """
        if len(self.nameservers) == 0:
            raise NoNameservers()
        for ns in self.nameservers:
            try:
                message = dns.message.make_query(name, type, rdclass=klass,
                                                 use_edns=self.edns, payload=self.payload,
                                                 want_dnssec=self.do)
            except TypeError: # Old DNS Python... Code here just as long as it lingers in some places
                try:
                    message = dns.message.make_query(name, type, rdclass=klass,
                                                     use_edns=self.edns, 
                                     want_dnssec=self.do)
                except dns.rdatatype.UnknownRdatatype:
                    raise UnknownRRtype()
                except dns.rdataclass.UnknownRdataclass:
                    raise UnknownClass()
                message.payload = self.payload
            except dns.rdatatype.UnknownRdatatype:
                raise UnknownRRtype()
            except dns.rdataclass.UnknownRdataclass:
                raise UnknownClass()
            if cd:
                message.flags |= dns.flags.CD
            done = False
            tests = 0
            while not done and tests < self.maximum:
                try:
                    if not tcp:
                        msg = dns.query.udp(message, ns, timeout=self.timeout)
                    else:
                        msg = dns.query.tcp(message, ns, timeout=self.timeout)
                    if msg.rcode() == dns.rcode.NOERROR:
                        done = True
                    elif msg.rcode() == dns.rcode.NXDOMAIN:
                        raise NoSuchDomainName()
                    elif msg.rcode() == dns.rcode.REFUSED:
                        if len(self.nameservers) == 1:
                            raise Refused()
                        else:
                            break
                    elif msg.rcode() == dns.rcode.SERVFAIL:
                        if len(self.nameservers) == 1:
                            raise Servfail()
                        else:
                            break
                    else:
                        raise UnknownError(msg.rcode())
                except dns.exception.Timeout:
                    tests += 1
            if done:
                response = copy.copy(msg)
                response.__class__ = Answer.ExtendedAnswer
                response.nameserver = ns
                response.qname = name
                return response
            elif len(self.nameservers) == 1:
                raise Timeout()
        # If we are still here, it means no name server answers
        raise NoPositiveAnswer()

    def set_edns(self, version=0, payload=DEFAULT_EDNS_SIZE, dnssec=False):
        """ version=0 means EDNS0, the original one. Use -1 for no EDNS """
        self.edns = version
        self.payload = payload
        self.do = dnssec

    def set_nameservers(self, nameservers):
        self.nameservers = nameservers
        
    def reset(self):
        self.edns = self.original_edns
        self.payload = self.original_payload
        self.nameservers = self.original_nameservers
        self.do = self.original_do
