from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import codecs
import collections
import errno
import smtplib
import socket


from django.core import mail
from django.template.loader import get_template
from django.utils import translation

import autoreg.conf


def _render_to_mail(templatename, context, fromaddr, toaddrs, request=None,
                   language=None, encoding='quoted-printable'):
  """Expand provided templatename and context, send the result
     by email to the indicated addresses."""

  t = get_template(templatename)

  # add possibly forgotten 'from' to generate valid mail headers
  if 'from' not in context:
    context['from'] = fromaddr

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
            % str(codecs.encode(val.strip().encode('utf-8'), 'quoted-printable'), 'ascii')
        # quoted-printable encoding can add '\n' which is an absolute no-no
        # in mail headers!
        val = val.replace('=\n', '').replace('=\r', '') \
                 .replace('\n', '').replace('\r', '')
        outh.append(key + ': ' + val)
      else:
        outh.append(line)
    else:
      outh.append(line)
  if encoding is not None:
    msg = '\n'.join(outh) + '\n\n' \
          + str(codecs.encode(body.encode('utf-8'), encoding), 'ascii')
  else:
    msg = '\n'.join(outh) + '\n\n' + body
  return msg


def render_to_mail(templatename, context, fromaddr, toaddrs, request=None,
                   language=None):
  """Send mail through Django, allowing mail capture during tests."""

  # Render the full message
  msg = _render_to_mail(templatename, context, fromaddr, toaddrs, request, language, encoding=None)

  # Extract fields for EmailMessage constructor
  headers, body = msg.split('\n\n', 1)
  header_dict = collections.OrderedDict()
  subject = None
  for hv in headers.split('\n'):
    h, v = hv.split(None, 1)
    assert(len(h))
    assert(h[-1] == ':')
    h = h[:-1]
    if h.lower() == 'subject':
      subject = v
    if h.lower() != 'content-transfer-encoding':
      header_dict[h] = v

  ret = True
  emsg = mail.EmailMessage(subject, body, from_email=fromaddr, to=toaddrs, bcc=[autoreg.conf.MAILBCC])
  try:
    emsg.send()
  except smtplib.SMTPRecipientsRefused as e:
    ret = False
  except socket.error as e:
    ret = False
    if e.errno != errno.ECONNREFUSED:
      raise

  return ret


def render_to_mail_direct(templatename, context, fromaddr, toaddrs, request=None,
                          language=None):
  msg = _render_to_mail(templatename, context, fromaddr, toaddrs, request, language,
                        encoding='quoted-printable')
  failed = False

  try:
    server = smtplib.SMTP()
    server.connect()
  except socket.error as e:
    if e.errno != errno.ECONNREFUSED:
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
