#!/usr/local/bin/python
# $Id$
#
# WSGI stub for invocation from Apache

import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'autoreg.arf.arf.settings'
os.environ['ARF_BASE'] = '/arf/'
os.environ['AUTOREG_DBSTRING'] = 'dbname=eu.org'

# This application object is used by the development server
# as well as any WSGI server configured to use this file.
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
