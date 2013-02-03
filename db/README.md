# dbconv

Convert DNS-LG "database" from YAML to different outputs.

## Usage

```
Usage: dbconv.py [options]

Print DNS-LG database

Options:
  -h, --help            show this help message and exit
  -f DBNAME, --database=DBNAME
                        Path to YAML database
  -j, --json            Output in JSON format
  -o ORIGIN, --origin=ORIGIN
                        Specify origin for DNS zone master format. (default: dns-lg)
  -t, --text            Plain-text output
  -x, --xml             XML format
  -z, --zone            master zone file format
```

## The following formats are currently supported

### Plain text

```
http://dns.bortzmeyer.org/                         Stéphane Bortzmeyer
http://dnslg.generic-nic.net/                      
http://dns-lg.nlnetlabs.nl/                        NLnetLabs
```

### Master zone file format

```
; Documentation of the existing DNS-LG instances.
;
; Generated at 2013-02-02T16:31:28
;
; This file contains a TXT RRset for inclusion into a
; zone master file. Each endpoint is a TXT record.
;
dns-lg     IN TXT  "http://dns.bortzmeyer.org/"                  ; Stéphane Bortzmeyer
           IN TXT  "http://dnslg.generic-nic.net/"               ; 
           IN TXT  "http://dns-lg.nlnetlabs.nl/"                 ; NLnetLabs
```

### JSON
```json
[
    {
        "endpoint": "http://dns.bortzmeyer.org/", 
        "contact": "St\u00e9phane Bortzmeyer"
    }, 
    {
        "endpoint": "http://dnslg.generic-nic.net/"
    },
]
```

### XML

```xml
<?xml version="1.0" ?>
<dns-lg>
  <!--Generated at 2013-02-02T19:03:51-->
  <endpoint contact="Stéphane Bortzmeyer">
    http://dns.bortzmeyer.org/
  </endpoint>
  <endpoint>
    http://dns-lg.tetaneutral.net/
  </endpoint>
</dns-lg>
```
