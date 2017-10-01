# Debug settings
#
# -*- coding: utf-8 -*-

import os

from .settings import *

DEBUG = True
LOCALE_PATHS = ( '/home/freenix/pb/autoreg/locale',)
SESSION_COOKIE_NAME = 'dsession_id'
INTERNAL_IPS=['192.168.0.0/24', '::1']
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False
