from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import autoreg.conf


# Generate a new secret seed for obfuscated email contact addresses.
# Cleanup expired secrets.
#
# To be run from time to time.

def new_handle_secret():
  import base64
  import os

  import psycopg2

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dbc = dbh.cursor()
  # use default expiration date for this table.

  # yields 32 ASCII bytes
  val = base64.b64encode(os.urandom(24)).decode('ascii')

  dbc.execute("INSERT INTO handle_secrets VALUES (%s)", (val,))
  assert dbc.rowcount == 1
  dbc.execute("DELETE FROM handle_secrets WHERE expires < NOW()")
  dbh.commit()


if __name__ == "__main__":
  new_handle_secret()
