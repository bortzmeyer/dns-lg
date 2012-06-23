import dns.resolver

class ExtendedAnswer(dns.resolver.Answer):
    def __init__(self, initial_answer):
        self.qname = initial_answer.qname
        self.rrsets = [initial_answer.rrset,]
        self.owner_name = initial_answer.rrset.name

