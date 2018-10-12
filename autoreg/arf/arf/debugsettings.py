# Debug settings
#
# -*- coding: utf-8 -*-

import os

from .settings import *

DEBUG = True

LOCALE_PATHS = ( '/home/pb/autoreg/locale',)

ALLOWED_HOSTS = [ 'devel.eu.org' ]

SESSION_COOKIE_NAME = 'dsession_id'
INTERNAL_IPS=['192.168.0.0/22', '2a02:8428:46c:5800::/56']
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False

#
# Application-specific settings
#

FORCEDEBUGMAIL='debug@eu.org'
TOTP_ISSUER='eu.org devel'
