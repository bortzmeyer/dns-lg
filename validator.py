#!/usr/bin/env python

from wsgiref.validate import validator
from wsgiref.simple_server import make_server

import DNSLG

port = 8080

querier = DNSLG.Querier()

validator_app = validator(querier.application)

httpd = make_server('', port, validator_app)
print "Listening on port %i...." % port
httpd.serve_forever()
