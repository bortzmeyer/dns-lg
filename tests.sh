#!/bin/sh
# -*- coding: utf-8 -*- 

# Send many different requests to a DNS-LG. No automatic testing, you
# have to read the results and interpret them yourself.
# To test HTML output validity, one may try 
# "curl -s ${URL}/${domain}\?format=HTML | xmllint --noout --dtdvalid /usr/share/xml/xhtml/schema/dtd/1.0/xhtml1-strict.dtd -"

URL=${DNSLG_URL:-'http://localhost:8080'}
WEB=${DNSLG_COMMAND:-'curl -s --write-out Return_code_%{http_code},_%{content_type},_%{size_download}_B,_%{time_total}_s\n\n'} 
DELAY=${DNSLG_DELAY:-0}

# Other sites describing deliberately broken DNS zones:
# http://www.test-aaaa-block.cl/
# http://www.dnssec-tools.org/testzone/index.html
# http://tjeb.nl/Projects/DNSSEC/

# See also validator.py for tests of the WSGI compliance

# TODO: test with another base

delay() {
    if [ $DELAY != 0 ]; then
	sleep $DELAY
    fi
}

unset http_proxy

echo Qname which exist, default qtype which exist
for domain in ietf.org gouvernement.fr; do
    ${WEB} ${URL}/${domain}
done
echo ""

echo Qname which exist, explicit qtype which exist
for domain in ietf.org gouvernement.fr; do
    ${WEB} ${URL}/${domain}/A
done
echo ""

echo Several answers
for domain in google.com facebook.com; do
    ${WEB} ${URL}/${domain}/A
done
echo ""
delay

echo Domain which does not exist
${WEB} ${URL}/doesnotexist.example
echo ""

echo Unknown type
${WEB} ${URL}/fr/XXXX
echo ""
delay

echo No data for this qtype
${WEB} ${URL}/fr/AAAA
${WEB} ${URL}/fr/SRV
${WEB} ${URL}/www.bortzmeyer.org/PTR
echo ""
delay

echo Existing qtypes, for different formats. ADDR is a pseudo-qtype.
for type in MX SOA NS DNSKEY AAAA ADDR; do
    for domain in ietf.org nic.fr; do
	for format in text zone xml html json; do
            echo "${type} ${domain} (${format})"
	    ${WEB} ${URL}/${domain}/${type}?format=${format}
            echo ""
	    delay
	done
    done
done
delay
for type in LOC; do
    # All AFNIC name servers have a LOC
    for domain in dns.lyn2.nic.fr uclouvain.sri.ucl.ac.be; do
	for format in text zone xml html json; do
	    ${WEB} ${URL}/${domain}/${type}?format=${format}
	done
    done
done
for type in DS; do
    for domain in bortzmeyer.fr isc.org; do
	for format in text zone xml html json; do
	    ${WEB} ${URL}/${domain}/${type}?format=${format}
	done
	delay
    done
done
for type in NAPTR; do
    for domain in http.uri.arpa education.lu mailclub.tel; do
	for format in text zone xml html json; do
	    ${WEB} ${URL}/${domain}/${type}?format=${format}
	done
	delay
    done
done
delay
for type in SRV; do
    for domain in _xmpp-client._tcp.dns-oarc.net _nicname._tcp.fr.; do
	for format in text zone xml html json; do
	    ${WEB} ${URL}/${domain}/${type}?format=${format}
	done
	delay
    done
done
for type in PTR; do
    for domain in 2.58.22.12.in-addr.arpa e.1.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.3.2.1.0.9.8.1.1.0.0.2.ip6.arpa; do
	for format in text zone xml html json; do
	    ${WEB} ${URL}/${domain}/${type}?format=${format}
	done
	delay
    done
done
echo ""
delay

echo We should be able to query the root. 
# TODO: But . is special in a URL and Apache modifies it (it works
# with the test server). Hence the pseudo-TLD root.
for format in text zone xml html json; do
    ${WEB} ${URL}/root/SOA?format=${format}
    ${WEB} ${URL}/./SOA?format=${format}
    ${WEB} ${URL}?format=${format}
    ${WEB} ${URL}/?format=${format}
    delay
done

echo Tests with CNAME and DNAME
for format in text zone xml html json; do
    ${WEB} ${URL}/alias-c.generic-nic.net/AAAA?format=${format}
    ${WEB} ${URL}/alias-c.generic-nic.net/CNAME?format=${format}
    ${WEB} ${URL}/alias-d.generic-nic.net/AAAA?format=${format}
    ${WEB} ${URL}/alias-d.generic-nic.net/DNAME?format=${format}
    ${WEB} ${URL}/www.testonly.sources.org/AAAA?format=${format}
    ${WEB} ${URL}/www.testonly.sources.org/DNAME?format=${format}
    delay
done
echo ""
delay

echo Reverse queries
for format in text zone xml html json; do
    ${WEB} ${URL}/192.5.5.241?format=${format}\&reverse=1
    ${WEB} ${URL}/2001:500:2f::f?format=${format}\&reverse=1
done
echo ""

echo Alternative resolver
for format in text zone xml html json; do
    # Google Public DNS, OARC's ODVR, Telecomix
    for resolver in 8.8.8.8 149.20.64.21 91.191.136.152; do	 
	${WEB} ${URL}/example.net/SOA?format=${format}\&server=${resolver}
    done
done
echo ""
delay

echo IDN
# Important to test all output formats since they have very different
# Unicode capabilities
for format in text zone xml html json; do
    ${WEB} ${URL}/latablée.fr/SOA?format=${format}
    ${WEB} ${URL}/latabl%C3%A9e.fr/SOA?format=${format}
    # The next one have an IDN name server
    ${WEB} ${URL}/elzévir.fr/NS?format=${format}
done
echo ""

echo Options
for format in text zone xml html json; do
    ${WEB} ${URL}/afnic.fr/SOA?format=${format}\&dodnssec=1
    ${WEB} ${URL}/afnic.fr/SOA?format=${format}\&tcp=1
    ${WEB} ${URL}/afnic.fr/SOA?format=${format}\&buffersize=0
    ${WEB} ${URL}/afnic.fr/SOA?format=${format}\&buffersize=512
    delay
done
echo ""
delay

echo "Test with names and data with special characters (such as & to crash the XML output)"
${WEB} ${URL}/dangerousrecord.broken-on-purpose.generic-nic.net/MX?format=xml
${WEB} ${URL}/dangerousrecord.broken-on-purpose.generic-nic.net/MX?format=json
${WEB} ${URL}/dangerous\<name.broken-on-purpose.generic-nic.net/TXT?format=xml
${WEB} ${URL}/dangerous\<name.broken-on-purpose.generic-nic.net/TXT?format=html
${WEB} ${URL}/dangerous{name.broken-on-purpose.generic-nic.net/TXT?format=json
echo ""

echo "Test with broken domains (all NS unreachable, for instance)"
${WEB} ${URL}/lame.broken-on-purpose.generic-nic.net/SOA?format=text
${WEB} ${URL}/lame2.broken-on-purpose.generic-nic.net/SOA?format=text
echo ""

echo "Test with invalid (DNSSEC) domains"
for domain in www.dnssec-failed.org. reverseddates-A.test.dnssec-tools.org; do
    ${WEB} ${URL}/${domain}/SOA?format=text
done
delay

# Various HTTP tricks

# This one requires curl, to have custom headers
echo Test methods other than GET (should be refused)
curl --head ${URL}/example.org/A
curl --data STUFF ${URL}/example.org/A
