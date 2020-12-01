from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import crypt
import random


from cryptography.fernet import Fernet


from .conf import ENCRYPT_KEY

# Fernet encryption/decryption object
_fernet = Fernet(ENCRYPT_KEY)

# parameters for SHA512 hashed passwords
CRYPT_SALT_LEN=16
CRYPT_ALGO='$6$'


def pwcrypt(passwd):
  """Compute a crypt(3) hash suitable for user authentication"""
  # Make a salt
  salt_chars = '0123456789abcdefghijklmnopqstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.'
  t = ''.join(random.SystemRandom().choice(salt_chars) \
              for i in range(CRYPT_SALT_LEN))
  return crypt.crypt(passwd, CRYPT_ALGO + t + '$')

def encrypt(text):
  return _fernet.encrypt(text.encode()).decode()

def decrypt(text):
  return _fernet.decrypt(text.encode()).decode()
