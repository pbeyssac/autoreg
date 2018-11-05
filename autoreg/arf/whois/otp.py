from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import base64
import io
import random


import pyotp
import qrcode


from django.db import IntegrityError, transaction


from autoreg.util import encrypt, decrypt

from .models import Otp


def _encrypt(secret, codes):
  encrypted_codes = encrypt(secret + ' ' + codes)
  codes = encrypted_codes
  secret = ''
  return secret, codes


def totp_save(cotp):
  """Save existing OTP entry."""
  cotp.secret, cotp.codes = _encrypt(cotp.secret, cotp.codes)
  cotp.save()


def totp_save_or_create(contact, secret, codes):
  """Make sure an OTP entry exists, create it if needed."""
  #
  # To avoid race conditions, UPDATE/INSERT loop as per
  # https://www.postgresql.org/docs/current/static/plpgsql-trigger.html#PLPGSQL-TRIGGER-SUMMARY-EXAMPLE
  #

  secret, codes = _encrypt(secret, codes)

  while True:
    try:
      with transaction.atomic():
        cotp = Otp(contact=contact, secret=secret, codes=codes, active=False)
        cotp.save()
        exists = False
    except IntegrityError:
      exists = True

    if not exists:
      break

    try:
      with transaction.atomic():
        cotp = Otp.objects.get(contact=contact)
    except Otp.DoesNotExist:
      exists = False

    if exists:
      cotp.codes = codes
      cotp.secret = secret
      cotp.active = False
      cotp.save()
      break


def totp_generate_recovery():
  t = []
  for i in range(10):
    t.append(''.join(random.SystemRandom().choice('0123456789')
                for i in range(8)))
  return t

def _constant_time_cmp(a, b):
  if len(a) != len(b):
    return 0
  diff = 0
  for i in range(len(a)):
    diff |= ord(a[i]) ^ ord(b[i])
  return 1 if diff == 0 else 0

def totp_check(otp, secret):
  totp = pyotp.TOTP(secret)
  return totp.verify(otp, valid_window=2)

def totp_count_valid_codes_old(codes):
  return len([c for c in codes.split() if c[-1] != '*'])

def totp_count_valid_codes(codes):
  return len([c for c in codes.split() if c[-1] != '*'])

def totp_get_record(handle):
  cotpl = Otp.objects.filter(contact__handle=handle)
  if cotpl.count() > 1:
    raise IntegrityError
  if cotpl.count() == 0:
    return None

  c = cotpl[0]
  # 174 = average of 100 (size of unencrypted entry)
  # and 248 (size of encrypted entry)
  # everything over 174 is assumed to be encrypted.
  if len(c.codes) > 174:
    secret, codes = decrypt(c.codes).split(' ', 1)
    c.codes = codes
    c.secret = secret
  else:
    # convert on the fly
    saved_secret, saved_codes = c.secret, c.codes
    totp_save(c)
    c.secret, c.codes = saved_secret, saved_codes
  return c

def totp_count_valid_codes_handle(handle):
  cotp = totp_get_record(handle)
  if not cotp:
    return 0
  return totp_count_valid_codes(cotp.codes)

def totp_is_active(handle):
  cotp = totp_get_record(handle)
  if not cotp:
    return False
  return cotp.active

def totp_or_recovery(otp, otprecord):
  """Try to authenticate using a 2-factor authentication
  code (return 'C'), or a recovery code (return 'R').
  Return False if authentication failed.
  """
  totp = pyotp.TOTP(otprecord.secret)
  if totp.verify(otp, valid_window=2):
    return 'C'
  codes = [c for c in otprecord.codes.split() if c[-1] != '*']

  ok = 0
  for c in codes:
    ok += _constant_time_cmp(c, otp)

  if ok == 0:
    return False

  codes = []
  for c in otprecord.codes.split():
    if c == otp:
      codes.append(c + '*')
    else:
      codes.append(c)
  codes = ' '.join(codes)
  otprecord.codes = codes
  otprecord.save()
  return 'R'

def totp_generate():
  secret = pyotp.random_base32()
  codes = totp_generate_recovery()
  return secret, codes

def totp_url(handle, issuer, secret):
  return pyotp.totp.TOTP(secret).provisioning_uri(handle, issuer)

def totp_qrcode(handle, issuer, secret):
  url = totp_url(handle, issuer, secret)
  qr = qrcode.QRCode(box_size=4)
  qr.add_data(url)
  qr.make(fit=True)
  #img = qrcode.make(url)
  img = qr.make_image()
  f = io.BytesIO()
  img.save(f)
  return str(base64.b64encode(f.getvalue()), 'ascii')
