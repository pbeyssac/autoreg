#!/usr/local/bin/python
# $Id$
#
# WSGI stub for invocation from Apache

import os
import sys

os.environ['DJANGO_SETTINGS_MODULE'] = 'autoreg.arf.debugsettings'
os.environ['ARF_BASE'] = '/darf/'
os.environ['AUTOREG_DBSTRING'] = 'dbname=eudevel'

sys.path = [ '/home/freenix/pb/autoreg/postgres/python' ] + sys.path

# This application object is used by the development server
# as well as any WSGI server configured to use this file.
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
