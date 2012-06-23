!/usr/bin/env python

import DNSLG

# Replace by suitable values.
# Note that some parameters can be set here and some via environment
# variables. There is no consistency (TODO).
email_admin = None
url_doc = None
url_css = None

querier = DNSLG.Querier(email_admin, url_doc, url_css)
application = querier.application
