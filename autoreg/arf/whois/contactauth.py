# $Id$
# Authentication backend using passwords from the whois contact database

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import crypt

import six

from autoreg.whois.db import suffixstrip

from django.contrib.auth.models import User

from .models import Contacts


class AuthBackend:
  def authenticate(self, username=None, password=None):
    username = suffixstrip(username.upper())
    ctlist = Contacts.objects.filter(handle=username)
    login_valid = (len(ctlist) == 1)
    if login_valid:
      ct = ctlist[0]
      cryptpass = ct.passwd
      if six.PY2:
        password = password.encode('UTF-8')
      pwd_valid = cryptpass and crypt.crypt(password,
                                            cryptpass) == cryptpass
    else:
      pwd_valid = False
    if login_valid and pwd_valid:
      try:
        user = User.objects.get(username=username)
      except User.DoesNotExist:
        # Create a new user. Note that we can set password
        # to anything, because it won't be checked; the password
        # from Contacts will.
        user = User(username=username, password='x')
        user.is_staff = False
        user.is_superuser = False
        user.email = ct.email
        user.date_joined = ct.created_on
        user.save()
      # update relevant fields of Django auth record if necessary
      if user.email != ct.email:
        user.email = ct.email
        user.save()
      return user
    return None

  def get_user(self, user_id):
    try:
      return User.objects.get(pk=user_id)
    except User.DoesNotExist:
      return None
