import errno
import smtplib

from django.template.loader import get_template
from django.template import Context

import autoreg.conf

def render_to_mail(templatename, context, fromaddr, toaddrs):
  """Expand provided templatename and context, send the result
     by email to the indicated addresses."""
  failed = False
  t = get_template(templatename)
  msg = t.render(Context(context))
  headers, body = msg.split('\n\n', 1)
  msg = headers + '\n\n' + body.encode('utf-8').encode('quoted-printable')

  try:
    server = smtplib.SMTP()
    server.connect()
  except socket.error as msg:
    if msg[0] != errno.ECONNREFUSED:
      raise
    failed = True
  if failed:
    return False

  try:
    recdict = server.sendmail(fromaddr, toaddrs + [ autoreg.conf.MAILBCC ], msg)
  except smtplib.SMTPRecipientsRefused as recdict:
    failed = True
  if failed:
    return False

  # XXX: should be more clever handling recipient errors
  if len(recdict):
    return False

  server.quit()

  return True
