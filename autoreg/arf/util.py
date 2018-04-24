from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import codecs
import errno
import smtplib

from django.template.loader import get_template
from django.utils import translation

import autoreg.conf

import six

def render_to_mail(templatename, context, fromaddr, toaddrs, request=None,
                   language=None):
  """Expand provided templatename and context, send the result
     by email to the indicated addresses."""

  failed = False
  t = get_template(templatename)

  # add possibly forgotten 'from' to generate valid mail headers
  if 'from' not in context:
    context['from'] = autoreg.conf.FROMADDR

  # Possibly activate another language just during the mail rendering,
  # instead of the current language, to get the mail
  # in the proper language (asynchronous user request, etc)
  #
  # Inspired from sample code in Django i18n documentation

  if language is not None:
    with translation.override(language):
      msg = t.render(context, request)
  else:
    msg = t.render(context, request)

  headers, body = msg.split('\n\n', 1)
  outh = []
  for line in headers.split('\n'):
    try:
      line.encode('ascii')
    except UnicodeEncodeError:
      if line[0] not in ' \n\t' and ':' in line:
        key, val = line.split(':', 1)
        val = '=?utf-8?Q?%s?=' \
            % six.text_type(codecs.encode(val.strip().encode('utf-8'), 'quoted-printable'), 'ascii')
        # quoted-printable encoding can add '\n' which is an absolute no-no
        # in mail headers!
        val = val.replace('=\n', '').replace('=\r', '') \
                 .replace('\n', '').replace('\r', '')
        outh.append(key + ': ' + val)
      else:
        outh.append(line)
    else:
      outh.append(line)
  msg = '\n'.join(outh) + '\n\n' \
        + six.text_type(codecs.encode(body.encode('utf-8'), 'quoted-printable'), 'ascii')

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
