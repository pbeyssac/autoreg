from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


from django import forms
from django.db.utils import IntegrityError
from django.conf import settings
import django.contrib.auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy, ugettext as _
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods


from autoreg.whois.db import suffixadd
from autoreg.common import domain_delete
from autoreg.conf import FROMADDR

from ..logs.models import log
from ..util import render_to_mail
from .models import Contacts
from . import otp
from .views import contactlogin_form

#
# Forms
#

class otpconfirm_form(forms.Form):
  otp = forms.CharField(max_length=8,
                        label=ugettext_lazy('Two-factor Authentication code'),
                        help_text=ugettext_lazy('One-Time Password'))

#
# 'view' functions called from urls.py and friends
#

#
# public pages
#

@require_http_methods(["GET", "POST"])
def login2fa(request):
  """Second login page for OTP code"""
  if request.method == "GET":
    if request.user.is_authenticated() and request.user.is_active:
      return HttpResponseRedirect(reverse('domainlist'))
    next = request.GET.get('next', None)
    #f = otplogin_form()
    #form = f.as_table()
    form = ''
    vars = { 'form': form, 'next': next }
    return render(request, 'whois/login2fa.html', vars)

  next = request.POST.get('next', reverse('domainlist'))
  vars = {'next': next}
  if request.user.is_authenticated():
    return HttpResponseRedirect(next)
  if not '1fa' in request.session:
    return HttpResponseRedirect(reverse('login'))
  handle = request.session['1fa']
  otppw = request.POST.get('otp', '')

  vars['form'] = contactlogin_form().as_table()

  cotp = otp.totp_get_record(handle)

  what = otp.totp_or_recovery(otppw, cotp)
  if not what:
    vars['msg'] = _("Sorry, your one-time password is incorrect")
    return render(request, 'whois/login2fa.html', vars)

  user = User.objects.get(username=handle)
  del request.session['1fa']
  log(handle, action='login')
  django.contrib.auth.login(request, user)

  if what == 'R':
    email = Contacts.objects.get(handle=handle).email
    #
    # A recovery code was used, notify by email
    #
    ncodes = otp.totp_count_valid_codes_handle(handle)
    # do this after login, to make sure a failure now
    # won't break the login process
    render_to_mail('whois/2fa-recovery.mail',
                   { 'to': email,
                     'remoteip': request.META.get('REMOTE_ADDR', None),
                     'handle': suffixadd(handle),
                     'absurl': request.build_absolute_uri(reverse('2fa-newrecovery')),
                      'ncodes': ncodes }, FROMADDR, [ email ],
                     request)

  return HttpResponseRedirect(next)

totplogin = login2fa

# private pages

@require_http_methods(["GET"])
@login_required
@cache_control(private=True, max_age=1)
def totp(request):
  """Set timed one-time password"""
  if not request.user.is_authenticated() or not request.user.is_active:
    return HttpResponseRedirect(reverse('login') + '?next=%s' % request.path)
  handle = request.user.username
  vars = {}

  if otp.totp_is_active(handle):
    vars['ncodes'] = otp.totp_count_valid_codes_handle(handle)
    return render(request, 'whois/2fa-set.html', vars)
  else:
    return render(request, 'whois/2fa-setup.html', vars)

@require_http_methods(["GET"])
@login_required
@cache_control(private=True, max_age=10)
def totpsetup1(request):
  """Display first setup page: recovery codes"""
  handle = request.user.username
  cl = Contacts.objects.filter(handle=handle)
  if cl.count() != 1:
    raise SuspiciousOperation
  c = cl[0]
  vars = {}

  secret, codelist = otp.totp_generate()
  codes = ' '.join(codelist)

  # Make sure an OTP entry exists, create it if needed.
  otp.totp_save_or_create(c, secret, codes)

  vars['codes'] = codelist
  vars['nexturl'] = '2fa-setup2'
  vars['nextlabel'] = _("Noted, continue")
  return render(request, 'whois/2fa-setup1.html', vars)

@require_http_methods(["POST"])
@login_required
@cache_control(private=True, max_age=10)
def totpnewrecovery(request):
  """Generate and display a new set of recovery codes"""
  handle = request.user.username
  cl = Contacts.objects.filter(handle=handle)
  if cl.count() != 1:
    raise SuspiciousOperation
  c = cl[0]
  vars = {}

  codes = otp.totp_generate_recovery()

  cotp = otp.totp_get_record(handle)
  if not cotp:
    # 2FA not configured on the account
    return HttpResponseRedirect(reverse(totp))

  cotp.codes = ' '.join(codes)
  otp.totp_save(cotp)

  vars['codes'] = codes
  vars['nexturl'] = '2fa'
  vars['nextlabel'] = _("Noted, done")

  email = c.email
  #
  # Notify by email
  #
  ncodes = otp.totp_count_valid_codes_handle(handle)
  render_to_mail('whois/2fa-newrecovery.mail',
                 { 'to': email,
                   'remoteip': request.META.get('REMOTE_ADDR', None),
                   'handle': suffixadd(handle),
                   'absurl': request.build_absolute_uri(reverse('2fa')),
                   'ncodes': ncodes }, FROMADDR, [ email ],
                   request)

  return render(request, 'whois/2fa-setup1.html', vars)

@require_http_methods(["GET", "POST"])
@login_required
@cache_control(private=True, max_age=10)
def totpsetup2(request):
  handle = request.user.username
  cl = Contacts.objects.filter(handle=handle)
  if cl.count() != 1:
    raise SuspiciousOperation
  c = cl[0]
  vars = {}

  cotp = otp.totp_get_record(handle)
  if not cotp:
    return HttpResponseRedirect(reverse(totp))

  if request.method == "POST":
    form = otpconfirm_form(request.POST)

    pw = request.POST.get('otp', '')
    if form.is_valid() and otp.totp_check(pw, cotp.secret):
      cotp.active = True
      otp.totp_save(cotp)
      return HttpResponseRedirect(reverse(totp))

    vars['msg'] = _("Wrong code, please try again")

  secret = cotp.secret
  qrcode = otp.totp_qrcode(suffixadd(handle), settings.TOTP_ISSUER, secret)
  vars['qrcode'] = qrcode
  vars['secret'] = secret
  vars['form'] = otpconfirm_form()
  return render(request, 'whois/2fa-setup2.html', vars)


@require_http_methods(["POST"])
@login_required
@cache_control(private=True, max_age=10)
def totpclear(request):
  handle = request.user.username
  vars = {}

  cotp = otp.totp_get_record(handle)
  if cotp is None:
    return HttpResponseRedirect(reverse(totp))

  form = otpconfirm_form(request.POST)
  pw = request.POST.get('otp', '')
  if form.is_valid() and otp.totp_check(pw, cotp.secret):
    cotp.delete()
    return HttpResponseRedirect(reverse(totp))

  vars['msg'] = _("Wrong code, please try again")
  vars['ncodes'] = otp.totp_count_valid_codes(cotp.codes)
  return render(request, 'whois/2fa-set.html', vars)
