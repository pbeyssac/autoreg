#!/usr/local/bin/python
# $Id$
#
# WSGI stub for invocation from Apache

import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'autoreg.arf.settings'
os.environ['ARF_BASE'] = '/darf/'
os.environ['AUTOREG_DBSTRING'] = 'dbname=eudevel'

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()
