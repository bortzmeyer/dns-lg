#!/usr/bin/env python

import dns
import dns.version as dnspythonversion
import base64
import platform
import pkg_resources 
import time
import struct

# TODO: Accept explicit requests for DNAME?
# TODO: DANE/TLSA record type. Not yet in DNS Python release
# (committed in the upstream git repository) so not easy...

import Answer

def to_hexstring(str):
    result = ""
    for char in str:
        result += ("%x" % ord(char))
    return result.upper()

def keylength(alg, key):
    """ Returns the length in bits """
    if alg == 5 or alg == 7 or alg == 8 or alg == 10:
        # RSA, RFC 3110
        firstbyte = struct.unpack("B", key[0])[0]
        if firstbyte > 0:
            exponentlength =  firstbyte + 1
        else:
            exponentlength = struct.unpack(">H", key[1:3])[0] + 3
        return (len(key)-exponentlength)*8
    else:
        # Unknown, best guess. Read the RFCs 6605 or 5933 to find out
        # the format of ECDSA or GOST keys.
        return len(key)*8
    
class Formatter():
    """ This ia the base class for the various Formatters. A formatter
    takes a "DNS answer" object and format it for a given output
    format (JSON, XML, etc). Implementing a new format means deriving
    this class and providing the required methods."""
    def __init__(self, domain):
        try:
            self.myversion = pkg_resources.require("DNS-LG")[0].version
        except pkg_resources.DistributionNotFound:
            self.myversion = "VERSION UNKNOWN"
        self.domain = domain
    
    def format(self, answer, qtype, qclass, flags, querier):
        """ Parameter "answer" must be of type
        Answer.ExtendedAnswer. "qtype" and "qclass" are strings, flags an integer
        and querier a DNSLG.Querier. This method changes the internal
        state of the Formatter, it returns nothing."""
        pass

    def result(self, querier):
        """ Returns the state of the Formatter, to be sent to the client."""
        return "NOT IMPLEMENTED IN THE BASE CLASS"

# TEXT
class TextFormatter(Formatter):

    def format(self, answer, qtype, qclass, flags, querier):
        # TODO: it would be nice one day to have a short format to
        # have only data, not headers. Or may be several short
        # formats, suitable for typical Unix text parsing tools. In
        # the mean time, use "zone" for that.
        self.output = ""
        if qclass != 'IN':
            qclass_text = ", class %s" % qclass
        else:
            qclass_text = ""
        self.output += "Query for: %s, type %s%s\n" % (self.domain.encode(querier.encoding),
                                                   qtype, qclass_text)
        str_flags = ""
        if flags & dns.flags.AD:
            str_flags += "/ Authentic Data "
        if flags & dns.flags.AA:
            str_flags += "/ Authoritative Answer "
        if flags & dns.flags.TC:
            str_flags += "/ Truncated Answer "
        self.output += "Flags: %s\n" % str_flags
        if answer is None:
            self.output += "[No data for this query type]\n"
        else:
            for rrset in answer.answer:
                for rdata in rrset:
                    if rdata.rdtype == dns.rdatatype.A or rdata.rdtype == dns.rdatatype.AAAA:
                        self.output += "IP address: %s\n" % rdata.address
                    elif rdata.rdtype == dns.rdatatype.MX:
                        self.output += "Mail exchanger: %s (preference %i)\n" % \
                                       (rdata.exchange, rdata.preference)
                    elif rdata.rdtype == dns.rdatatype.TXT:
                        self.output += "Text: %s\n" % " ".join(rdata.strings)
                    elif rdata.rdtype == dns.rdatatype.SPF:
                        self.output += "SPF policy: %s\n" % " ".join(rdata.strings)
                    elif rdata.rdtype == dns.rdatatype.SOA:
                        self.output += "Start of zone authority: serial number %i, zone administrator %s, master nameserver %s\n" % \
                                       (rdata.serial, rdata.rname, rdata.mname)
                    elif rdata.rdtype == dns.rdatatype.NS:
                        self.output += "Name server: %s\n" % rdata.target
                    elif rdata.rdtype == dns.rdatatype.DS:
                        self.output += "Delegation of signature: key %i, hash type %i, hash %s\n" % \
                                       (rdata.key_tag, rdata.digest_type, to_hexstring(rdata.digest))
                    elif rdata.rdtype == dns.rdatatype.DLV:
                        self.output += "Delegation of signature: key %i, hash type %i\n" % \
                                       (rdata.key_tag, rdata.digest_type)
                    elif rdata.rdtype == dns.rdatatype.RRSIG:
                        pass # Should we show signatures?
                    elif rdata.rdtype == dns.rdatatype.NSEC or rdata.rdtype == dns.rdatatype.NSEC3:
                        pass # Should we show NSEC*?
                    elif rdata.rdtype == dns.rdatatype.LOC:
                        self.output += "Location: longitude %i degrees %i' %i\" latitude %i degrees %i' %i\" altitude %f\n" % \
                                       (rdata.longitude[0], rdata.longitude[1], rdata.longitude[2],
                                        rdata.latitude[0], rdata.latitude[1], rdata.latitude[2],
                                        rdata.altitude)
                    elif rdata.rdtype == dns.rdatatype.URI:
                        self.output += "URI: %s\n" % (rdata.target) # TODO display priority and weight?
                    elif rdata.rdtype == dns.rdatatype.SRV:
                        self.output += "Service location: server %s, port %i, priority %i, weight %i\n" % \
                                       (rdata.target, rdata.port, rdata.priority, rdata.weight)
                    elif rdata.rdtype == dns.rdatatype.PTR:
                        self.output += "Target: %s\n" % rdata.target
                    elif rdata.rdtype == dns.rdatatype.CNAME:
                        self.output += "Canonical name: %s\n" % rdata.target
                    elif rdata.rdtype == dns.rdatatype.DNSKEY:
                        self.output += "DNSSEC key: "
                        try:
                            key_tag = dns.dnssec.key_id(rdata)
                            self.output += "tag %i " % key_tag
                        except AttributeError:
                            # key_id appeared only in dnspython 1.9. Not
                            # always available on 2012-05-17
                            pass
                        self.output += "algorithm %i, length %i bits, flags %i\n" % (rdata.algorithm, keylength(rdata.algorithm, rdata.key), rdata.flags)
                    elif rdata.rdtype == dns.rdatatype.NSEC3PARAM:
                        self.output += "NSEC3PARAM: algorithm %i, iterations %i, salt %s\n" % (rdata.algorithm, rdata.iterations, to_hexstring(rdata.salt)) 
                    elif rdata.rdtype == dns.rdatatype.SSHFP:
                        self.output += "SSH fingerprint: algorithm %i, digest type %i, fingerprint %s\n" % \
                                       (rdata.algorithm, rdata.fp_type, to_hexstring(rdata.fingerprint))
                    elif rdata.rdtype == dns.rdatatype.NAPTR:
                        self.output += ("Naming Authority Pointer: flags \"%s\", order %i, " + \
                                       "preference %i, rexegp \"%s\" -> replacement \"%s\", " + \
                                       "services \"%s\"\n") % \
                                       (rdata.flags, rdata.order, rdata.preference,
                                       rdata.regexp, str(rdata.replacement), rdata.service)
                    else:
                        self.output += "Unknown record type %i: (DATA)\n" % rdata.rdtype
                if rdata.rdtype != dns.rdatatype.RRSIG and \
                       rdata.rdtype != dns.rdatatype.NSEC and \
                       rdata.rdtype != dns.rdatatype.NSEC3:
                    self.output += "TTL: %i\n" % rrset.ttl
        self.output += "Resolver queried: %s\n" % answer.nameserver
        self.output += "Query done at: %s\n" % time.strftime("%Y-%m-%d %H:%M:%SZ",
                                                             time.gmtime(time.time()))
        self.output += "Query duration: %s\n" % querier.delay
        if querier.description:
            self.output += "Service description: %s\n" % querier.description
        self.output += "DNS Looking Glass %s, DNSpython version %s, Python version %s %s on %s\n" % \
                       (self.myversion,
                        dnspythonversion.version, platform.python_implementation(),
                        platform.python_version(), platform.system())
        
    def result(self, querier):
        return self.output


# ZONE FILE
class ZoneFormatter(Formatter):

    def format(self, answer, qtype, qclass, flags, querier):
        self.output = ""
        if qclass != 'IN':
            qclass_text = ", class %s" % qclass
        else:
            qclass_text = ""
        self.output += "; Question: %s, type %s%s\n" % (self.domain.encode(querier.encoding),
                                                      qtype, qclass_text)
        str_flags = ""
        if flags & dns.flags.AD:
            str_flags += " ad "
        if flags & dns.flags.AA:
            str_flags += " aa  "
        if flags & dns.flags.TC:
            str_flags += " tc "
        if str_flags != "":
            self.output += "; Flags:" + str_flags + "\n"
        self.output += "\n"
        if answer is None:
            self.output += "; No data for this type\n"
        else:
            for rrset in answer.answer:
                for rdata in rrset:
                    # TODO: do not hardwire the class
                    if rdata.rdtype != dns.rdatatype.RRSIG:
                        self.output += "%s\tIN\t" % answer.qname # TODO: do not repeat the name if there is a RRset
                    # TODO: it could use some refactoring: most (but _not all_) of types
                    # use the same code.
                    if rdata.rdtype == dns.rdatatype.A:
                        self.output += "A\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.AAAA:
                        self.output += "AAAA\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.MX:
                        self.output += "MX\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.SPF:
                        self.output += "SPF\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.TXT:
                        self.output += "TXT\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.SOA:
                        self.output += "SOA\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.NS:
                        self.output += "NS\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.PTR:
                        self.output += "PTR\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.CNAME:
                        self.output += "CNAME\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.LOC:
                        self.output += "LOC\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.URI:
                        self.output += "URI\t%s\n" % rdata.to_text().encode(querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DNSKEY:
                        self.output += "DNSKEY\t%s" % rdata.to_text()
                        try:
                            key_tag = dns.dnssec.key_id(rdata)
                            self.output += "; key ID = %i\n" % key_tag
                        except AttributeError:
                            # key_id appeared only in dnspython 1.9. Not
                            # always available on 2012-05-17
                            self.output += "\n"
                    elif rdata.rdtype == dns.rdatatype.NSEC3PARAM:
                        self.output += "NSEC3PARAM\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.DS:
                        self.output += "DS\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.DLV:
                        self.output += "DLV\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.SSHFP:
                        self.output += "SSHFP\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.NAPTR:
                        self.output += "NAPTR\t%s\n" % rdata.to_text()
                    elif rdata.rdtype == dns.rdatatype.RRSIG:
                        pass # Should we show signatures?
                    elif rdata.rdtype == dns.rdatatype.SRV:
                        self.output += "SRV\t%s\n" % rdata.to_text()
                    else:
                        # dnspython dumps the types it knows. TODO: uses that?
                        self.output += "TYPE%i ; DATA %s\n" % (rdata.rdtype, rdata.to_text())
                if rdata.rdtype != dns.rdatatype.RRSIG:
                    self.output += "; TTL: %i\n\n" % rrset.ttl # TODO: put it in the zone, not as a comment
        self.output += "\n; Server: %s\n" % answer.nameserver
        self.output += "; When: %s\n" % time.strftime("%Y-%m-%d %H:%M:%SZ",
                                                             time.gmtime(time.time()))
        self.output += "; Query duration: %s\n" % querier.delay
        if querier.description:
            self.output += "; Service description: %s\n" % querier.description
        self.output += "; DNS Looking Glass %s, DNSpython version %s, Python version %s %s on %s\n" % \
                       (self.myversion, dnspythonversion.version,
                        platform.python_implementation(),
                        platform.python_version(), platform.system())
                
    def result(self, querier):
        return self.output


# JSON
import json
# http://docs.python.org/library/json.html
class JsonFormatter(Formatter):

    def format(self, answer, qtype, qclass, flags, querier):
        self.object = {}
        self.object['ReturnCode'] = "NOERROR"
        self.object['QuestionSection'] = {'Qname': self.domain, 'Qtype': qtype, 'Qclass': qclass}
        if flags & dns.flags.AD:
            self.object['AD'] = True
        if flags & dns.flags.AA:
            self.object['AA'] = True
        if flags & dns.flags.TC:
            self.object['TC'] = True
        self.object['AnswerSection'] = []
        if answer.answer is not None:
            for rrset in answer.answer:
                for rdata in rrset: # TODO: sort them? For instance by preference for MX?
                    if rdata.rdtype == dns.rdatatype.A:
                        self.object['AnswerSection'].append({'Type': 'A', 'Address': rdata.address})
                    elif  rdata.rdtype == dns.rdatatype.AAAA:
                        self.object['AnswerSection'].append({'Type': 'AAAA', 'Address': rdata.address})
                    elif rdata.rdtype == dns.rdatatype.LOC:
                        self.object['AnswerSection'].append({'Type': 'LOC',
                                                             'Longitude': '%f' % rdata.float_longitude,
                                                             'Latitude': '%f' % rdata.float_latitude,
                                                             'Altitude': '%f' % rdata.altitude})
                    elif rdata.rdtype == dns.rdatatype.URI:
                        self.object['AnswerSection'].append({'Type': 'URI',
                                                             'Target': '%s' % rdata.target,
                                                             'Priority': '%i' % rdata.priority,
                                                             'Weight': '%i' % rdata.weight})
                    elif rdata.rdtype == dns.rdatatype.PTR:
                        self.object['AnswerSection'].append({'Type': 'PTR',
                                                             'Target': str(rdata.target)})
                    elif rdata.rdtype == dns.rdatatype.CNAME:
                        self.object['AnswerSection'].append({'Type': 'CNAME',
                                                             'Target': str(rdata.target)})
                    elif rdata.rdtype == dns.rdatatype.MX:
                        self.object['AnswerSection'].append({'Type': 'MX', 
                                                             'MailExchanger': str(rdata.exchange),
                                                             'Preference': rdata.preference})
                    elif rdata.rdtype == dns.rdatatype.TXT:
                        self.object['AnswerSection'].append({'Type': 'TXT', 'Text': " ".join(rdata.strings)})
                    elif rdata.rdtype == dns.rdatatype.SPF:
                        self.object['AnswerSection'].append({'Type': 'SPF', 'Text': " ".join(rdata.strings)})
                    elif rdata.rdtype == dns.rdatatype.SOA:
                        self.object['AnswerSection'].append({'Type': 'SOA', 'Serial': rdata.serial,
                                                             'MasterServerName': str(rdata.mname),
                                                             'MaintainerName': str(rdata.rname),
                                                             'Refresh': rdata.refresh,
                                                             'Retry': rdata.retry,
                                                             'Expire': rdata.expire,
                                                             'Minimum': rdata.minimum,
                                                             })
                    elif rdata.rdtype == dns.rdatatype.NS:
                        self.object['AnswerSection'].append({'Type': 'NS', 'Target': str(rdata.target)})
                    elif rdata.rdtype == dns.rdatatype.DNSKEY:
                        returned_object = {'Type': 'DNSKEY',
                                           'Length': keylength(rdata.algorithm, rdata.key),
                                          'Algorithm': rdata.algorithm,
                                          'Flags': rdata.flags}
                        try:
                            key_tag = dns.dnssec.key_id(rdata)
                            returned_object['Tag'] = key_tag
                        except AttributeError:
                            # key_id appeared only in dnspython 1.9. Not
                            # always available on 2012-05-17
                            pass
                        self.object['AnswerSection'].append(returned_object)
                    elif rdata.rdtype == dns.rdatatype.NSEC3PARAM:   
                        self.object['AnswerSection'].append({'Type': 'NSEC3PARAM', 'Algorithm': rdata.algorithm, 'Iterations': rdata.iterations, 'Salt': to_hexstring(rdata.salt), 'Flags': rdata.flags}) 
                    elif rdata.rdtype == dns.rdatatype.DS:
                        self.object['AnswerSection'].append({'Type': 'DS', 'DelegationKey': rdata.key_tag,
                                                             'DigestType': rdata.digest_type})
                    elif rdata.rdtype == dns.rdatatype.DLV:
                        self.object['AnswerSection'].append({'Type': 'DLV', 'DelegationKey': rdata.key_tag,
                                                             'DigestType': rdata.digest_type})
                    elif rdata.rdtype == dns.rdatatype.RRSIG:
                        pass # Should we show signatures?
                    elif rdata.rdtype == dns.rdatatype.SSHFP:
                        self.object['AnswerSection'].append({'Type': 'SSHFP',
                                                             'Algorithm': rdata.algorithm,
                                                             'DigestType': rdata.fp_type,
                                                             'Fingerprint': to_hexstring(rdata.fingerprint)})
                    elif rdata.rdtype == dns.rdatatype.NAPTR:
                        self.object['AnswerSection'].append({'Type': 'NAPTR',
                                                             'Flags': rdata.flags,
                                                             'Services': rdata.service,
                                                             'Order': rdata.order,
                                                             'Preference': rdata.preference,
                                                             'Regexp': rdata.regexp,
                                                             'Replacement': str(rdata.replacement)})
                    elif rdata.rdtype == dns.rdatatype.SRV:
                        self.object['AnswerSection'].append({'Type': 'SRV', 'Server': str(rdata.target),
                                                             'Port': rdata.port,
                                                             'Priority': rdata.priority,
                                                             'Weight': rdata.weight})
                    else:
                        self.object['AnswerSection'].append({'Type': "unknown %i" % rdata.rdtype}) 
                    if rdata.rdtype != dns.rdatatype.RRSIG:
                        self.object['AnswerSection'][-1]['TTL'] = rrset.ttl
                        self.object['AnswerSection'][-1]['Name'] = str(rrset.name)
        try:
            duration = querier.delay.total_seconds()
        except AttributeError: # total_seconds appeared only with Python 2.7
            delay = querier.delay
            duration = (delay.days*86400) + delay.seconds + \
                       (float(delay.microseconds)/1000000.0)
        self.object['Query'] = {'Server': answer.nameserver,
                                'Time': time.strftime("%Y-%m-%d %H:%M:%SZ",
                                                      time.gmtime(time.time())),
                                'Duration': duration}
        if querier.description:
            self.object['Query']['Description'] = querier.description
        self.object['Query']['Versions'] = "DNS Looking Glass %s, DNSpython version %s, Python version %s %s on %s" % \
                       (self.myversion, dnspythonversion.version,
                        platform.python_implementation(),
                        platform.python_version(), platform.system())

            
    def result(self, querier):
        return json.dumps(self.object, indent=True) + "\n"


# XML
# http://www.owlfish.com/software/simpleTAL/
from simpletal import simpleTAL, simpleTALES, simpleTALUtils
xml_template = """
<result>
 <query>
    <question><qname tal:content="qname"/><qtype tal:content="qtype"/></question>
    <server><resolver tal:content="resolver"/><duration tal:content="duration"/><time tal:content="time"/><description tal:condition="description" tal:content="description"/><versions tal:condition="version" tal:content="version"/></server>
 </query>
 <response>
    <!-- TODO: query ID -->
    <ad tal:condition="ad" tal:content="ad"/><tc tal:condition="tc" tal:content="tc"/><aa tal:condition="aa" tal:content="aa"/>
    <!-- No <anscount>, it is useless in XML. -->
    <answers tal:condition="rrsets">
      <rrset tal:replace="structure rrset" tal:repeat="rrset rrsets"/>
    </answers>
 </response>
</result>
"""
set_xml_template = """
<RRSet tal:condition="records" class="IN" tal:attributes="owner ownername; type type; ttl ttl"><record tal:repeat="record records" tal:replace="structure record"/></RRSet>
"""
a_xml_template = """
<A tal:attributes="address address"/>
"""
aaaa_xml_template = """
<AAAA tal:attributes="ip6address address"/>
"""
mx_xml_template = """
<MX tal:attributes="preference preference; exchange exchange"/>
"""
ns_xml_template = """
<NS tal:attributes="nsdname name"/>
"""
srv_xml_template = """
<SRV tal:attributes="priority priority; weight weight; port port; target name"/>
"""
txt_xml_template = """
<TXT tal:attributes="rdata text"/>
"""
spf_xml_template = """
<SPF tal:attributes="rdata text"/>
"""
loc_xml_template = """
<LOC tal:attributes="longitude longitude; latitude latitude; altitude altitude"/>
"""
uri_xml_template = """
<URI tal:attributes="target target; priority priority; weight weight"/>
"""
ptr_xml_template = """
<PTR tal:attributes="ptrdname name"/>
"""
cname_xml_template = """
<CNAME tal:attributes="host target"/>
"""
# TODO: NSEC3PARAM not in draft-daley-dns-schema-00
nsec3param_xml_template = """
<NSEC3PARAM tal:attributes="algorithm algorithm; flags flags; iterations iterations"/>
"""
ds_xml_template = """
<DS tal:attributes="keytag keytag; algorithm algorithm; digesttype digesttype; digest digest"/>
"""
dlv_xml_template = """
<DLV tal:attributes="keytag keytag; algorithm algorithm; digesttype digesttype; digest digest"/>
"""
# TODO: keytag is an extension to the Internet-Draft
dnskey_xml_template = """
<DNSKEY tal:attributes="flags flags; protocol protocol; algorithm algorithm; length length; publickey key; keytag keytag"/>
"""
sshfp_xml_template = """
<SSHFP tal:attributes="algorithm algorithm; fptype fptype; fingerprint fingerprint"/>
"""
naptr_xml_template = """
<NAPTR tal:attributes="flags flags; order order; preference preference; services services; regexp regexp; replacement replacement"/>
"""
soa_xml_template = """
<SOA tal:attributes="mname mname; rname rname; serial serial; refresh refresh; retry retry; expire expire; minimum minimum"/>
"""
# TODO: how to keep the comments of a template in TAL's output?
unknown_xml_template = """
<binaryRR tal:attributes="rtype rtype; rdlength rdlength; rdata rdata"/> <!-- Unknown type -->
"""
# TODO: Why is there a rdlength when you can deduce it from the rdata?
# That's strange in a non-binary format like XML.
class XmlFormatter(Formatter):

    def format(self, answer, qtype, qclass, flags, querier):
        self.xml_template = simpleTAL.compileXMLTemplate (xml_template)
        self.set_template = simpleTAL.compileXMLTemplate (set_xml_template)
        self.a_template = simpleTAL.compileXMLTemplate (a_xml_template)
        self.aaaa_template = simpleTAL.compileXMLTemplate (aaaa_xml_template)
        self.mx_template = simpleTAL.compileXMLTemplate (mx_xml_template)
        self.srv_template = simpleTAL.compileXMLTemplate (srv_xml_template)
        self.txt_template = simpleTAL.compileXMLTemplate (txt_xml_template)
        self.spf_template = simpleTAL.compileXMLTemplate (spf_xml_template)
        self.loc_template = simpleTAL.compileXMLTemplate (loc_xml_template)
        self.ns_template = simpleTAL.compileXMLTemplate (ns_xml_template)
        self.ptr_template = simpleTAL.compileXMLTemplate (ptr_xml_template)
        self.cname_template = simpleTAL.compileXMLTemplate (cname_xml_template)
        self.soa_template = simpleTAL.compileXMLTemplate (soa_xml_template)
        self.ds_template = simpleTAL.compileXMLTemplate (ds_xml_template)
        self.nsec3param_template = simpleTAL.compileXMLTemplate (nsec3param_xml_template)
        self.dlv_template = simpleTAL.compileXMLTemplate (dlv_xml_template)
        self.dnskey_template = simpleTAL.compileXMLTemplate (dnskey_xml_template)
        self.sshfp_template = simpleTAL.compileXMLTemplate (sshfp_xml_template)
        self.naptr_template = simpleTAL.compileXMLTemplate (naptr_xml_template)
        self.unknown_template = simpleTAL.compileXMLTemplate (unknown_xml_template)
        self.context = simpleTALES.Context(allowPythonPath=False)
        self.acontext = simpleTALES.Context(allowPythonPath=False)
        self.rcontext = simpleTALES.Context(allowPythonPath=False)
        self.context.addGlobal ("qname", self.domain)
        self.context.addGlobal ("qtype", qtype)
        self.context.addGlobal ("resolver", answer.nameserver)
        try:
            duration = querier.delay.total_seconds()
        except AttributeError: # total_seconds appeared only with Python 2.7
            delay = querier.delay
            duration = (delay.days*86400) + delay.seconds + \
                       (float(delay.microseconds)/1000000.0)
        self.context.addGlobal ("duration", duration)
        self.context.addGlobal ("time", time.strftime("%Y-%m-%d %H:%M:%SZ",
                                                      time.gmtime(time.time())))
        self.context.addGlobal ("description", querier.description)
        self.context.addGlobal ("version",
                                "DNS Looking Glass %s, DNSpython version %s, Python version %s %s on %s\n" % \
                                (self.myversion, dnspythonversion.version,
                                 platform.python_implementation(),
                                 platform.python_version(), platform.system()))
        addresses = []
        if answer is not None:
            self.rrsets = []
            if flags & dns.flags.AD:
                ad = 1
            else:
                ad = 0
            self.context.addGlobal ("ad", ad)
            if flags & dns.flags.TC:
                tc = 1
            else:
                tc = 0
            self.context.addGlobal ("tc", tc)
            if flags & dns.flags.AA:
                aa = 1
            else:
                aa = 0
            self.context.addGlobal ("aa", aa)
            # TODO: class
            for rrset in answer.answer:
                records = []
                self.acontext.addGlobal ("ttl", rrset.ttl)
                self.acontext.addGlobal ("type", dns.rdatatype.to_text(rrset.rdtype))
                for rdata in rrset:
                    icontext = simpleTALES.Context(allowPythonPath=False)
                    iresult = simpleTALUtils.FastStringOutput()
                    if rdata.rdtype == dns.rdatatype.A or rdata.rdtype == dns.rdatatype.AAAA:
                        icontext.addGlobal ("address", rdata.address)
                        if rdata.rdtype == dns.rdatatype.A:
                            self.a_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                        else:
                            self.aaaa_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SRV:
                        icontext.addGlobal ("priority", rdata.priority)
                        icontext.addGlobal ("weight", rdata.weight)
                        icontext.addGlobal ("port", rdata.port)
                        icontext.addGlobal ("name", rdata.target)
                        self.srv_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.MX:
                        icontext.addGlobal ("preference", rdata.preference)
                        icontext.addGlobal ("exchange", rdata.exchange)
                        self.mx_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NSEC3PARAM:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("flags", rdata.flags)
                        icontext.addGlobal ("iterations", rdata.iterations)
                        self.nsec3param_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DS:
                        icontext.addGlobal ("keytag", rdata.key_tag)
                        icontext.addGlobal ("digesttype", rdata.digest_type)
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("digest", to_hexstring(rdata.digest))
                        self.ds_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DLV:
                        icontext.addGlobal ("keytag", rdata.key_tag)
                        icontext.addGlobal ("digesttype", rdata.digest_type)
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("digest", to_hexstring(rdata.digest)) 
                        self.dlv_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DNSKEY:
                        try:
                            key_tag = dns.dnssec.key_id(rdata)
                            icontext.addGlobal ("keytag", key_tag)
                        except AttributeError:
                            # key_id appeared only in dnspython 1.9. Not
                            # always available on 2012-05-17
                            pass                  
                        icontext.addGlobal ("protocol", rdata.protocol)
                        icontext.addGlobal ("flags", rdata.flags)
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("length", keylength(rdata.algorithm, rdata.key))
                        icontext.addGlobal ("key", to_hexstring(rdata.key))
                        self.dnskey_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SSHFP:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("fptype", rdata.fp_type)
                        icontext.addGlobal ("fingerprint", to_hexstring(rdata.fingerprint))
                        self.sshfp_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NAPTR:
                        icontext.addGlobal ("flags", rdata.flags)
                        icontext.addGlobal ("services", rdata.service)
                        icontext.addGlobal ("order", rdata.order)
                        icontext.addGlobal ("preference", rdata.preference)
                        regexp = unicode(rdata.regexp, "UTF-8")
                        icontext.addGlobal ("regexp",
                                            regexp)
                        # Yes, there is Unicode in NAPTRs, see
                        # mailclub.tel for instance. We assume it will
                        # always be UTF-8
                        icontext.addGlobal ("replacement", rdata.replacement)
                        self.naptr_template.expand (icontext, iresult,
                                                    suppressXMLDeclaration=True, 
                                                    outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.TXT:
                        # Yes, some people add Unicode in TXT records,
                        # see mailclub.tel for instance. We assume
                        # UTF-8
                        text = unicode(" ".join(rdata.strings), "UTF-8")
                        icontext.addGlobal ("text", text)
                        self.txt_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SPF:
                        icontext.addGlobal ("text", " ".join(rdata.strings))
                        self.spf_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.PTR:
                        icontext.addGlobal ("name", rdata.target)
                        self.ptr_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.CNAME:
                        icontext.addGlobal ("target", rdata.target)
                        self.cname_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.LOC:
                        icontext.addGlobal ("longitude", rdata.float_longitude)
                        icontext.addGlobal ("latitude", rdata.float_latitude)
                        icontext.addGlobal ("altitude", rdata.altitude)
                        self.loc_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.URI:
                        icontext.addGlobal ("target", rdata.target)
                        icontext.addGlobal ("weight", rdata.weight)
                        icontext.addGlobal ("priority", rdata.priority)
                        self.loc_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NS:
                        icontext.addGlobal ("name", rdata.target)
                        # TODO: translate Punycode domain names back to Unicode?
                        self.ns_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True)
                    elif rdata.rdtype == dns.rdatatype.SOA:
                        icontext.addGlobal ("rname", rdata.rname)
                        icontext.addGlobal ("mname", rdata.mname)
                        icontext.addGlobal ("serial", rdata.serial)
                        icontext.addGlobal ("refresh", rdata.refresh)
                        icontext.addGlobal ("retry", rdata.retry)
                        icontext.addGlobal ("expire", rdata.expire)
                        icontext.addGlobal ("minimum", rdata.minimum)
                        self.soa_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)                    
                    else:
                        icontext.addGlobal ("rtype", rdata.rdtype)
                        icontext.addGlobal ("rdlength", 0)  # TODO: useless, anyway (and
                        # no easy way to compute it in dnspython)
                        # TODO: rdata
                        self.unknown_template.expand (icontext, iresult,
                                                           suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)   
                    records.append(unicode(iresult.getvalue(), querier.encoding))
                else:
                    pass # TODO what to send back when no data for this QTYPE?
                if records:
                    self.acontext.addGlobal ("records", records)
                    self.acontext.addGlobal ("ttl", rrset.ttl)
                    iresult = simpleTALUtils.FastStringOutput()
                    self.set_template.expand (self.acontext, iresult,
                                              suppressXMLDeclaration=True, 
                                              outputEncoding=querier.encoding)
                    self.rrsets.append(unicode(iresult.getvalue(), querier.encoding))
        else:
            self.rrsets = None

    def result(self, querier):
        result = simpleTALUtils.FastStringOutput()
        self.context.addGlobal("rrsets", self.rrsets)
        self.xml_template.expand (self.context, result, 
                                                      outputEncoding=querier.encoding)
        return result.getvalue()


# HTML
html_template = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
    <title tal:content="title"/>
    <link tal:condition="css" rel="stylesheet" type="text/css" tal:attributes="href css"/>
    <link rel="author" href="http://www.bortzmeyer.org/static/moi.html"/>
    <link tal:condition="opensearch" rel="search"
           type="application/opensearchdescription+xml" 
           tal:attributes="href opensearch"
           title="DNS Looking Glass" />
    <meta http-equiv="Content-Type" tal:attributes="content contenttype"/>
    <meta name="robots" content="noindex,nofollow"/>
 </head>
 <body>
    <h1 tal:content="title"/>
    <div class="body">
    <p tal:condition="distinctowner">Response is name <span class="hostname" tal:content="ownername"/>.</p><p tal:condition="flags">Response flags are: <span tal:replace="flags"/>.</p>
    <div class="rrsets" tal:repeat="rrset rrsets">
    <ul tal:condition="rrset/records">
      <li tal:repeat="record rrset/records" tal:content="structure record"/>
      <li tal:condition="rrset/ttl">(Time-to-Live of this answer is <span tal:replace="rrset/ttl"/>)</li>
    </ul>
    </div>
    <p tal:condition="not: rrsets">No data was found.</p>
    <p>Result obtained from resolver(s) <span class="hostname" tal:content="resolver"/> at <span tal:replace="datetime"/>. Query took <span tal:replace="duration"/>.</p>
    </div>
    <hr class="endsep"/>
    <p><span tal:condition="email">Service managed by <span class="email" tal:content="email"/>. </span><span tal:condition="doc"> See <a tal:attributes="href doc">details and documentation</a>.</span><span tal:condition="description_html" tal:content="structure description_html"/><span tal:condition="description" tal:content="description"/> / <span tal:condition="versions" tal:content="structure versions"/></p>
 </body>
</html>
"""
version_html_template = """
<span>DNS Looking Glass "<span tal:replace="myversion"/>", <a href="http://www.dnspython.org/">DNSpython</a> version <span tal:replace="dnsversion"/>, <a href="http://www.python.org/">Python</a> version <span tal:replace="pyversion"/></span>
"""
address_html_template = """
<span>IP address: <a class="address" tal:attributes="href path" tal:content="address"/></span>
"""
mx_html_template = """
<span>Mail Exchanger: <a class="hostname" tal:attributes="href path" tal:content="hostname"/> (preference <span tal:replace="pref"/>)</span>
"""
# TODO: better presentation of "admin" (replacement of . by @ and mailto: URL). See nic.in for an example of a broken zone, in that respect.
# TODO: better presentation of intervals? (Weeks, days, etc)
soa_html_template = """
<span>Start Of Authority: Zone administrator <span tal:replace="admin"/>, master server <a class="hostname" tal:attributes="href path" tal:content="master"/>, serial number <span tal:replace="serial"/>, refresh interval <span tal:replace="refresh"/> s, retry interval <span tal:replace="retry"/> s, expiration delay <span tal:replace="expire"/> s, negative reply TTL <span tal:replace="minimum"/> s</span>
"""
ns_html_template = """
<span>Name Servers: <a class="hostname" tal:attributes="href path" tal:content="hostname"/></span>
"""
ptr_html_template = """
<span>Associated name: <a class="hostname" tal:attributes="href path" tal:content="hostname"/></span>
"""
cname_html_template = """
<span>Canonical name: <a class="hostname" tal:attributes="href path" tal:content="target"/></span>
"""
srv_html_template = """
<span>Service: Priority <span tal:content="priority"/>, weight <span tal:content="weight"/>, host <a class="hostname" tal:attributes="href path" tal:content="hostname"/>, port <span tal:content="port"/>,</span>
"""
txt_html_template = """
<span>Text: <span tal:content="text"/></span>
"""
spf_html_template = """
<span>SPF record: <span tal:content="text"/></span>
"""
nsec3param_html_template = """
<span>NSEC3 parameters: hash type <span tal:replace="algorithm"/>, <span tal:replace="iterations"/> iterations, flags <span tal:replace="flags"/></span>
"""
ds_html_template = """
<span>Secure Delegation: Key <span tal:replace="keytag"/> (hash type <span tal:replace="digesttype"/>)</span>
"""
dlv_html_template = """
<span>Lookaside Secure Delegation: Key <span tal:replace="keytag"/> (hash type <span tal:replace="digesttype"/>)</span>
"""
dnskey_html_template = """
<span>DNSSEC key: <span tal:condition="keytag"><span tal:replace="keytag"/>, </span>algorithm <span tal:replace="algorithm"/>, length <span tal:replace="length"/> bits, flags <span tal:replace="flags"/></span>
"""
# TODO display the key tag, the inception and expiration time?
rrsig_html_template = """
<span>DNSSEC signature</span>
"""
nsec_html_template = """
<span>NSEC or NSEC3 record</span>
"""
sshfp_html_template = """
<span>SSH fingerprint: Algorithm <span tal:replace="algorithm"/>, Fingerprint type <span tal:replace="fptype"/>, fingerprint <span tal:replace="fingerprint"/></span>
"""
naptr_html_template = """
<span>Naming Authority Pointer: Flags "<span tal:replace="flags"/>", Service(s) "<span tal:replace="services"/>", order <span tal:replace="order"/> and preference <span tal:replace="preference"/>, regular expression <span class="naptr_regexp" tal:content="regexp"/>, replacement <span class="domainname" tal:content="replacement"/></span>
"""
# TODO: link to Open Street Map
loc_html_template = """
<span>Location: <span tal:replace="longitude"/> / <span tal:replace="latitude"/> (altitude <span tal:replace="altitude"/>)</span>
"""
uri_html_template = """
<span>Priority: <span tal:replace="priority"/>, <span tal:replace="weight"/>, <a class="hostname" tal:attributes="href target" tal:content="target"/></span>
"""
unknown_html_template = """
<span>Unknown record type (<span tal:replace="rrtype"/>)</span>
"""
class HtmlFormatter(Formatter):

    def link_of(self, host, querier, reverse=False):
        if querier.base_url == "":
            url = '/'
        else:
            url = querier.base_url
        base = url + str(host)
        if not reverse:
            base += '/ADDR'
        base += '?format=HTML'
        if reverse:
            base += '&reverse=1'
        return base

    def pretty_duration(self, duration):
        """ duration is in seconds """
        weeks = duration/(86400*7)
        days = (duration-(86400*7*weeks))/86400
        hours = (duration-(86400*7*weeks)-(86400*days))/3600
        minutes = (duration-(86400*7*weeks)-(86400*days)-(3600*hours))/60
        seconds = duration-(86400*7*weeks)-(86400*days)-(3600*hours)-(60*minutes)
        result = ""
        empty_result = True
        if weeks != 0:
            if weeks > 1:
                plural = "s"
            else:
                plural = ""
            result += "%i week%s" % (weeks, plural)
            empty_result = False
        if days != 0:
            if not empty_result:
                result += ", "
            if days > 1:
                plural = "s"
            else:
                plural = ""
            result += "%i day%s" % (days, plural)
            empty_result = False
        if hours != 0:
            if not empty_result:
                result += ", "
            if hours > 1:
                plural = "s"
            else:
                plural = ""
            result += "%i hour%s" % (hours, plural)
            empty_result = False
        if minutes != 0:
            if not empty_result:
                result += ", "
            if minutes > 1:
                plural = "s"
            else:
                plural = ""
            result += "%i minute%s" % (minutes, plural)
            empty_result = False
        if not empty_result:
            result += ", "
        if seconds > 1:
            plural = "s"
        else:
            plural = ""
        result += "%i second%s" % (seconds, plural)
        return result
    
    def format(self, answer, qtype, qclass, flags, querier):
        self.template = simpleTAL.compileXMLTemplate (html_template)
        self.address_template = simpleTAL.compileXMLTemplate (address_html_template)
        self.version_template = simpleTAL.compileXMLTemplate (version_html_template)
        self.mx_template = simpleTAL.compileXMLTemplate (mx_html_template)
        self.soa_template = simpleTAL.compileXMLTemplate (soa_html_template)
        self.ns_template = simpleTAL.compileXMLTemplate (ns_html_template)
        self.ptr_template = simpleTAL.compileXMLTemplate (ptr_html_template)
        self.cname_template = simpleTAL.compileXMLTemplate (cname_html_template)
        self.srv_template = simpleTAL.compileXMLTemplate (srv_html_template)
        self.txt_template = simpleTAL.compileXMLTemplate (txt_html_template)
        self.spf_template = simpleTAL.compileXMLTemplate (spf_html_template)
        self.loc_template = simpleTAL.compileXMLTemplate (loc_html_template)
        self.uri_template = simpleTAL.compileXMLTemplate (uri_html_template)
        self.nsec3param_template = simpleTAL.compileXMLTemplate (nsec3param_html_template)
        self.ds_template = simpleTAL.compileXMLTemplate (ds_html_template)
        self.dlv_template = simpleTAL.compileXMLTemplate (dlv_html_template)
        self.dnskey_template = simpleTAL.compileXMLTemplate (dnskey_html_template)
        self.rrsig_template = simpleTAL.compileXMLTemplate (rrsig_html_template)
        self.nsec_template = simpleTAL.compileXMLTemplate (nsec_html_template)
        self.sshfp_template = simpleTAL.compileXMLTemplate (sshfp_html_template)
        self.naptr_template = simpleTAL.compileXMLTemplate (naptr_html_template)
        self.unknown_template = simpleTAL.compileXMLTemplate (unknown_html_template)
        self.context = simpleTALES.Context(allowPythonPath=False)
        self.context.addGlobal ("title", "Query for domain %s, type %s" % \
                                    (self.domain, qtype))
        self.context.addGlobal ("resolver", answer.nameserver)
        self.context.addGlobal ("email", querier.email_admin)
        self.context.addGlobal ("doc", querier.url_doc)
        self.context.addGlobal("contenttype", 
                               "text/html; charset=%s" % querier.encoding)
        self.context.addGlobal ("css", querier.url_css)
        self.context.addGlobal ("opensearch", querier.url_opensearch)
        self.context.addGlobal ("datetime", time.strftime("%Y-%m-%d %H:%M:%SZ",
                                                          time.gmtime(time.time())))
        self.context.addGlobal("duration", str(querier.delay))
        if querier.description_html:
            self.context.addGlobal("description_html", querier.description_html)
        elif querier.description:
            self.context.addGlobal("description", querier.description)
        iresult = simpleTALUtils.FastStringOutput()
        icontext = simpleTALES.Context(allowPythonPath=False)
        icontext.addGlobal("pyversion", platform.python_implementation() + " " + 
                           platform.python_version() + " on " + platform.system())
        icontext.addGlobal("dnsversion", dnspythonversion.version)
        icontext.addGlobal("myversion", self.myversion)
        self.version_template.expand (icontext, iresult,
                                      suppressXMLDeclaration=True, 
                                      outputEncoding=querier.encoding)
        self.context.addGlobal("versions", unicode(iresult.getvalue(), querier.encoding))
        str_flags = ""
        if flags & dns.flags.AD:
            str_flags += "/ Authentic Data "
        if flags & dns.flags.AA:
            str_flags += "/ Authoritative Answer "
        if flags & dns.flags.TC:
            str_flags += "/ Truncated Answer "
        if str_flags != "":
            self.context.addGlobal ("flags", str_flags)
        if answer is not None:
            self.rrsets = []
            icontext = simpleTALES.Context(allowPythonPath=False)
            for rrset in answer.answer:
                records = []
                for rdata in rrset:
                    iresult = simpleTALUtils.FastStringOutput()
                    if rdata.rdtype == dns.rdatatype.A or rdata.rdtype == dns.rdatatype.AAAA:
                        icontext.addGlobal ("address", rdata.address)
                        icontext.addGlobal ("path", self.link_of(rdata.address,
                                                                 querier,
                                                                 reverse=True))
                        self.address_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True, 
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SOA:
                        icontext.addGlobal ("master", rdata.mname)
                        icontext.addGlobal ("path", self.link_of(rdata.mname, querier))
                        icontext.addGlobal("admin", rdata.rname) # TODO: replace first point by @
                        icontext.addGlobal("serial", rdata.serial)
                        icontext.addGlobal("refresh", rdata.refresh)
                        icontext.addGlobal("retry", rdata.retry)
                        icontext.addGlobal("expire", rdata.expire)
                        icontext.addGlobal("minimum", rdata.minimum)
                        self.soa_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.MX:
                        icontext.addGlobal ("hostname", rdata.exchange)
                        icontext.addGlobal ("path", self.link_of(rdata.exchange, querier))
                        icontext.addGlobal("pref", rdata.preference)
                        self.mx_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NS:
                        icontext.addGlobal ("hostname", rdata.target)
                        # TODO: translate back the Punycode name
                        # servers to Unicode with
                        # encodings.idna.ToUnicode?
                        icontext.addGlobal ("path", self.link_of(rdata.target, querier))
                        self.ns_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.PTR:
                        icontext.addGlobal ("hostname", rdata.target)
                        icontext.addGlobal ("path", self.link_of(rdata.target, querier))
                        self.ptr_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.CNAME:
                        icontext.addGlobal ("target", rdata.target)
                        icontext.addGlobal ("path", self.link_of(rdata.target, querier))
                        self.cname_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SRV:
                        icontext.addGlobal ("hostname", rdata.target)
                        icontext.addGlobal ("path", self.link_of(rdata.target, querier))
                        icontext.addGlobal ("priority", rdata.priority)
                        icontext.addGlobal ("weight", rdata.weight)
                        icontext.addGlobal ("port", rdata.port)
                        self.srv_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.TXT:
                        text = unicode(" ".join(rdata.strings), "UTF-8")
                        icontext.addGlobal ("text", text)
                        self.txt_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SPF:
                        icontext.addGlobal ("text", "\n".join(rdata.strings))
                        self.spf_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.LOC:
                        # TODO: expanded longitude and latitude instead of floats?
                        icontext.addGlobal ("longitude", rdata.float_longitude)
                        icontext.addGlobal ("latitude", rdata.float_latitude)
                        icontext.addGlobal ("altitude", rdata.altitude)
                        self.loc_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.URI:
                        icontext.addGlobal ("target", rdata.target)
                        icontext.addGlobal ("weight", rdata.weight)
                        icontext.addGlobal ("priority", rdata.priority)
                        self.uri_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NSEC3PARAM:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("iterations", rdata.iterations)
                        icontext.addGlobal ("flags", rdata.flags)
                        self.nsec3param_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DS:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("digesttype", rdata.digest_type)
                        icontext.addGlobal ("digest", rdata.digest)
                        icontext.addGlobal ("keytag", rdata.key_tag)
                        self.ds_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DLV:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("digesttype", rdata.digest_type)
                        icontext.addGlobal ("digest", rdata.digest)
                        icontext.addGlobal ("keytag", rdata.key_tag)
                        self.dlv_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.DNSKEY:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("length", keylength(rdata.algorithm, rdata.key))
                        icontext.addGlobal ("protocol", rdata.protocol)
                        icontext.addGlobal ("flags", rdata.flags)
                        try:
                            key_tag = dns.dnssec.key_id(rdata)
                            icontext.addGlobal ("keytag", key_tag)
                        except AttributeError:
                            # key_id appeared only in dnspython 1.9. Not
                            # always available on 2012-05-17
                            pass
                        self.dnskey_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.RRSIG:
                        self.rrsig_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NSEC or rdata.rdtype == dns.rdatatype.NSEC3:
                        # It can happen with QTYPE=ANY
                        self.nsec_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.SSHFP:
                        icontext.addGlobal ("algorithm", rdata.algorithm)
                        icontext.addGlobal ("fptype", rdata.fp_type)
                        icontext.addGlobal ("fingerprint", to_hexstring(rdata.fingerprint))
                        self.sshfp_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    elif rdata.rdtype == dns.rdatatype.NAPTR:
                        icontext.addGlobal ("flags", rdata.flags)
                        icontext.addGlobal ("order", rdata.order)
                        icontext.addGlobal ("preference", rdata.preference)
                        icontext.addGlobal ("services", rdata.service)
                        icontext.addGlobal ("regexp", unicode(rdata.regexp,
                                                              "UTF-8")) # UTF-8 rdata is found in the wild
                        icontext.addGlobal ("replacement", rdata.replacement)
                        self.naptr_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    else:
                        icontext.addGlobal ("rrtype", rdata.rdtype)
                        self.unknown_template.expand (icontext, iresult,
                                                       suppressXMLDeclaration=True,
                                                      outputEncoding=querier.encoding)
                    records.append(unicode(iresult.getvalue(), querier.encoding))
                self.rrsets.append({'ttl': self.pretty_duration(rrset.ttl),
                                    'records': records})
        else:
            self.rrsets = None

    def result(self, querier):
        result = simpleTALUtils.FastStringOutput()        
        self.context.addGlobal("rrsets", self.rrsets)
        self.template.expand (self.context, result, 
                              outputEncoding=querier.encoding,
                              docType='<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">')
        return (result.getvalue() + "\n")
