from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import datetime
import random
import time


from django.db import connection


from .models import Tokens


# chars allowed in passwords or reset/validation tokens
allowed_chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'

#
# Helper functions
#

def token_find(contact_id, action):
  """Find existing token(s)"""
  # Expire old tokens beforehand
  dbc = connection.cursor()
  dbc.execute('DELETE FROM arf_tokens WHERE expires < NOW()')
  return Tokens.objects.filter(contact_id=contact_id, action=action)

def token_clear(contact_id, action):
  """Cleanup pre-existing token(s)"""
  token_find(contact_id, action).delete()

def token_set(contact_id, action, args=None, ttl=3600):
  """Create a token for the indicated action on the indicated contact"""
  sr = random.SystemRandom()
  token = ''.join(sr.choice(allowed_chars) for i in range(16))
  t = time.time()
  now = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
  expires = datetime.datetime.fromtimestamp(t + ttl, datetime.timezone.utc)
  tk = Tokens(contact_id=contact_id, date=now, expires=expires,
              token=token, action=action, args=args)
  tk.save()
  return token
