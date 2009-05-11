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

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()
