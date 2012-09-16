import dns.resolver
import dns.message

class ExtendedAnswer(dns.message.Message):
    
    def __init__(self, initial_msg):
        #for field in initial_msg.__attr__:
        #    self.field = initial_msg.field
        super(ExtendedAnswer, self).__init__()
        self.nameserver = None
        self.qname = None
        
