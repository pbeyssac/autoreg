#!/usr/local/bin/python
# $Id$
#
# WSGI stub for invocation from Apache

import os
import sys

os.environ['DJANGO_SETTINGS_MODULE'] = 'autoreg.arf.arf.debugsettings'
os.environ['ARF_BASE'] = '/arf/'

sys.path = [ '/home/freenix/pb/autoreg' ] + sys.path

# This application object is used by the development server
# as well as any WSGI server configured to use this file.
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
