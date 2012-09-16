import copy

import dns.message
import dns.resolver
import Answer

class Timeout(Exception):
    pass

class NoSuchDomainName(Exception):
    pass

class UnknownError(Exception):
    pass

class Resolver():
    
    def __init__(self, nameservers=None, maximum=3, timeout=0.5,
                 edns_version=0, edns_payload=4096):
        # TODO CRIT: DNSSEC
        # TODO: ednsflags such as NSID
        """ A "None" value for the parameter nameservers means to use
        the system's default resolver(s). Otherwise, this parameter
        is an *array* of the IP addresses of the resolvers.
        edns_version=0 means EDNS0, the original one. Use -1 for no EDNS """
        self.maximum = maximum
        self.timeout = timeout
        self.original_edns = edns_version
        self.original_payload = edns_payload
        if nameservers is None:
            self.original_nameservers = dns.resolver.get_default_resolver().nameservers
        else:
            # TODO: test it is an iterable? And of length > 0?
            self.original_nameservers = nameservers
        self.edns = self.original_edns
        self.payload = self.original_payload
        self.nameservers = self.original_nameservers
        
    def query(self, name, type, tcp=False):
        # TODO CRIT : TCP
        """ The returned value is a DNSLG.Answer """
        for ns in self.nameservers:
            try:
                message = dns.message.make_query(name, type,
                                                 use_edns=self.edns, payload=self.payload,
                                                 want_dnssec=True)
            except TypeError: # Old DNS Python... Code here just as long as it lingers in some places
                message = dns.message.make_query(name, type, use_edns=0, 
                                     want_dnssec=True)
                message.payload = 4096
            done = False
            tests = 0
            while not done and tests < self.maximum:
                try:
                    msg = dns.query.udp(message, ns, timeout=self.timeout)
                    if msg.rcode() == dns.rcode.NOERROR:
                        done = True
                    elif msg.rcode() == dns.rcode.NXDOMAIN:
                        raise NoSuchDomainName()
                    # TODO CRIT: if REFUSED or SERVFAIL, tries the next resolver?
                    else:
                        raise UnknownError(msg.rcode)
                except dns.exception.Timeout:
                    tests += 1
            if done:
                response = copy.copy(msg)
                response.__class__ = Answer.ExtendedAnswer
                response.nameserver = ns
                response.qname = name
                return response
        # If we are still here, it means no name server answers
        raise Timeout()

    def set_edns(self, version=0, payload=4096, dnssec=False):
        """ version=0 means EDNS0, the original one. Use -1 for no EDNS """
        self.edns = version
        self.payload = None

    def set_nameservers(self, nameservers):
        self.nameservers = nameservers
        
    def reset(self):
        self.edns = self.original_edns
        self.payload = self.original_payload
        self.nameservers = self.original_nameservers
