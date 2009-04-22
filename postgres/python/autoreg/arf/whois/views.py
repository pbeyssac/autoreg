# $Id$

import crypt
import datetime
import os
import random
import re
import smtplib
import time

from autoreg.whois.db import HANDLESUFFIX,suffixstrip,suffixadd

import django.contrib.auth
from django.template.loader import get_template
from django.template import Context
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django import forms
from django.forms.widgets import PasswordInput
from django.views.decorators.cache import cache_control

from models import Whoisdomains,Contacts

URIBASE = '/arf/'
URILOGIN = URIBASE + 'login/'
URICHPASS = URIBASE + 'contact/chpass/'
URICHANGE = URIBASE + 'contact/change/'
URIDOMAINS = URIBASE + 'contact/domains/'
URILOGOUT = URIBASE + 'logout/'
URIRESET1 = URIBASE + 'contact/reset/'
URLCHPASS = 'https://eu.org' + URICHPASS
URLRESET2 = 'https://eu.org' + URIBASE + 'contact/doreset/'
FROMADDR = 'noreply@eu.org'
RESET_TOKEN_TTL = 3*86400

# for debug purposes
MAILBCC="pb@eu.org"

#
# Helper functions
#

def _makesalt():
  """Return a salt suitable for MD5-based crypt"""
  salt_chars = '0123456789abcdefghijklmnopqstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.'
  t = ''.join(random.SystemRandom().choice(salt_chars) for i in range(8))
  return '$1$' + t + '$'

def _render_to_mail(templatename, context, fromaddr, toaddrs):
  """Expand provided templatename and context, send the result
     by email to the indicated addresses."""
  t = get_template(templatename)
  msg = t.render(Context(context))
  server = smtplib.SMTP()
  server.connect()
  server.sendmail(fromaddr, toaddrs + [ MAILBCC ], msg)
  server.quit()

#
# Forms
#

class contactbyemail_form(forms.Form):
  email = forms.EmailField(max_length=100)

class contactbyhandle_form(forms.Form):
  handle = forms.CharField(max_length=15, initial=HANDLESUFFIX, help_text='Your handle')

class contact_form(forms.Form):
  pn1 = forms.CharField(max_length=60, label="Name")
  em1 = forms.EmailField(max_length=64, label="E-mail")
  ad1 = forms.CharField(max_length=80, label="Organization")
  ad2 = forms.CharField(max_length=80, label="Address (line 1)")
  ad3 = forms.CharField(max_length=80, label="Address (line 2)", required=False)
  ad4 = forms.CharField(max_length=80, label="Address (line 3)", required=False)
  ad5 = forms.CharField(max_length=80, label="Address (line 4)", required=False)
  ad6 = forms.CharField(max_length=80, label="Country", required=False)
  ph1 = forms.RegexField(max_length=30, label="Phone Number", regex='^\+?[\d\s#\-\(\)\[\]\.]+$', required=False)
  fx1 = forms.RegexField(max_length=30, label="Fax Number", regex='^\+?[\d\s#\-\(\)\[\]\.]+$', required=False)
  p1 = forms.CharField(max_length=20, label='Password', required=False, widget=PasswordInput)
  p2 = forms.CharField(max_length=20, label='Confirm Password', required=False, widget=PasswordInput)
  policy = forms.BooleanField(label="I accept the Policy", required=False)

class contactlogin_form(forms.Form):
  handle = forms.CharField(max_length=15, initial=HANDLESUFFIX, help_text='Your handle')
  password = forms.CharField(max_length=30, help_text='Your password', widget=PasswordInput)

class resetpass_form(forms.Form):
  resettoken = forms.CharField(max_length=30)
  pass1 = forms.CharField(max_length=20, label='New Password', widget=PasswordInput)
  pass2 = forms.CharField(max_length=20, label='Confirm Password', widget=PasswordInput)

class chpass_form(forms.Form):
  pass0 = forms.CharField(max_length=30, label='Current Password', widget=PasswordInput)
  pass1 = forms.CharField(max_length=30, label='New Password', widget=PasswordInput)
  pass2 = forms.CharField(max_length=30, label='Confirm Password', widget=PasswordInput)

#
# 'view' functions called from urls.py and friends
#

#
# public pages
#

def login(request):
  """Login page"""
  if request.method == "GET":
    next = request.GET.get('next', URIBASE)
    if request.user.is_authenticated():
      return HttpResponseRedirect(next)
    f = contactlogin_form()
    form = f.as_table()
    request.session.set_test_cookie()
    if next == URIBASE:
      next = None
    return render_to_response('whois/login.html',
                              {'form': form, 'posturi': request.path,
                               'next': next})
  elif request.method == "POST":
    next = request.POST.get('next', URIBASE)
    if request.user.is_authenticated():
      #django.contrib.auth.logout(request)
      return HttpResponseRedirect(next)
      #return HttpResponse('OK')
    if not request.session.test_cookie_worked():
      return render_to_response('whois/login.html',
                                {'form': contactlogin_form().as_table(),
                                 'next': request.path,
                                 'msg': "Please enable cookies"})
    else:
      #request.session.delete_test_cookie()
      pass
    handle = request.POST.get('handle', '').upper()
    password = request.POST.get('password', '')
    handle = suffixstrip(handle)

    user = django.contrib.auth.authenticate(username=handle, password=password)
    if user is not None:
      if user.is_active:
        django.contrib.auth.login(request, user)
        return HttpResponseRedirect(next)
      else:
        return render_to_response('whois/login.html',
                                  {'form': contactlogin_form().as_table(),
                                   'next': request.path,
                                   'msg': "Sorry, your account has been disabled"})
    else:
      return render_to_response('whois/login.html',
                                {'form': contactlogin_form().as_table(),
                                 'next': request.path,
                                 'msg': "Your username and/or password is incorrect"})

def makeresettoken(request):
  """Password reset step 1: send a reset token to the contact email address"""
  allowed_chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  if request.method == "GET":
    f = contactbyhandle_form()
    form = f.as_table()
    return render_to_response('whois/resetpass.html',
                              {'form': form, 'posturi': request.path})
  elif request.method == "POST":
    handle = request.POST.get('handle', '').upper()
    fullhandle = handle
    handle = suffixstrip(handle)
    ctl = Contacts.objects.filter(handle=handle)
    if len(ctl) == 0:
      return render_to_response('whois/contactnotfound.html',
                                {'handle': suffixadd(handle),
                                 'next': request.path})
    if len(ctl) != 1:
      return HttpResponse("Internal Error")
    ct = ctl[0]
    sr = random.SystemRandom()
    ct.pw_reset_token = ''.join(sr.choice(allowed_chars) for i in range(16))
    ct.pw_reset_token_date = datetime.datetime.today()
    ct.save()
    _render_to_mail('whois/resetpass.mail',
                    { 'from': FROMADDR, 'to': ct.email,
                      'handle': fullhandle,
                      'reseturl': URLRESET2 + handle,
                      'token': ct.pw_reset_token }, FROMADDR, [ ct.email ])
    return render_to_response('whois/tokensent.html',
                              {'handle': suffixadd(handle), 'next': URIBASE})

def resetpass2(request, handle):
  """Password reset step 2:
     check provided reset token and force indicated password
     on the desginated contact."""
  f = resetpass_form()
  form = f.as_table()
  if request.method == "GET":
    return render_to_response('whois/resetpass2.html',
                              {'form': form, 'posturi': request.path})
  elif request.method == "POST":
    ctl = Contacts.objects.filter(handle=handle)
    if len(ctl) < 1:
      return render_to_response('whois/resetpass2.html',
                                {'form': form, 'posturi': request.path})
    ct = ctl[0]
    pass1 = request.POST.get('pass1', 'A')
    pass2 = request.POST.get('pass2', 'B')
    if pass1 != pass2:
      return render_to_response('whois/resetpass2.html',
                                {'form': form, 'posturi': request.path,
                                 'msg': "They don't match, try again"})
    if len(pass1) < 8:
      return render_to_response('whois/resetpass2.html',
                                {'form': form, 'posturi': request.path,
                                 'msg': "Password should be at least 8 chars"})
    token = request.POST.get('resettoken', 'C')
    if token != ct.pw_reset_token:
      return render_to_response('whois/resetpass2.html',
                                {'form': form, 'posturi': request.path,
                                 'msg': "Invalid reset token"})
    if ct.pw_reset_token_date < datetime.datetime.fromtimestamp(time.time()-RESET_TOKEN_TTL):
      return render_to_response('whois/msgnext.html',
                                {'next': URIRESET1,
                                 'msg': "Reset code has expired, please try to get a new one."})
    ct.passwd = crypt.crypt(pass1, _makesalt())
    ct.pw_reset_token = None
    ct.save()
    return render_to_response('whois/passchanged.html',
                              {'next': URIBASE})

def contactcreate(request):
  """Contact creation page"""
  if request.method == "GET":
    form = contact_form()
  elif request.method == "POST":
    form = contact_form(request.POST)
    if form.is_valid():
      d = {}
      d['pn'] = [ form.cleaned_data['pn1'] ]
      d['em'] = [ form.cleaned_data['em1'] ]
      ad = []
      for i in ['ad1', 'ad2', 'ad3', 'ad4', 'ad5', 'ad6']:
        a = form.cleaned_data.get(i, None)
        if a is not None:
          ad.append(a)
      d['ad'] = ad
      d['ph'] = [ form.cleaned_data.get('ph', None) ]
      d['fx'] = [ form.cleaned_data.get('fx', None) ]
      # XXX: use META
      d['ch'] = [ (os.environ.get('REMOTE_ADDR', 'REMOTE_ADDR_NOT_SET'), None) ]
      send_mail(
        'Feedback from your site',
        'CHECK\n\n', 'pb@fasterix.frmug.org',
        ['pb@fasterix.frmug.org'])
      return HttpResponse("Done")
  return render_to_response('whois/contactcreate.html',
                            {'form': form, 'posturi': request.path})

def contact(request, handle):
  """Contact display from handle"""
  c = Contacts.objects.get(handle=handle)
  return render_to_response('whois/contact.html',
                            {'contact': c,
                             'address_list': c.addr.split('\n')[:-1]})

def domain(request, fqdn):
  """Whois from domain FQDN"""
  f = fqdn.upper()
  try:
    dom = Whoisdomains.objects.get(fqdn=f)
  except Whoisdomains.DoesNotExist:
    dom = None
  if dom is None:
    return render_to_response('whois/domainnotfound.html', {'fqdn': fqdn})
  cl = dom.domaincontact_set.all()
  return render_to_response('whois/fqdn.html',
                            {'whoisdomain': dom, 'domaincontact_list': cl})

def resetpass_old(request):
  """Deprecated: unprotected password reset page"""
  allowed_chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  clearpass = ''
  cryptpass = ''
  if request.method == "GET":
    f = contactbyemail_form()
    form = f.as_table()
    return render_to_response('whois/contactp1.html',
                              {'form': form, 'posturi': request.path})
  elif request.method == "POST":
    email = request.POST.get('email', '')
    ctl = Contacts.objects.filter(email=email)
    if len(ctl) >= 1:
      sr = random.SystemRandom()
      clearpass = ''.join(sr.choice(allowed_chars) for i in range(8))
      cryptpass = crypt.crypt(clearpass, _makesalt())

      hlist = []
      for ct in ctl:
        ct.passwd = cryptpass
        hlist.append(suffixadd(ct.handle))
        #ct.save()

      _render_to_mail('whois/changepass.mail',
                      { 'from': FROMADDR, 'to': email,
                        'handles': hlist,
                        'changeurl': URLCHPASS,
                        'newpass': clearpass }, FROMADDR, [ email ])
      return HttpResponse("OK")

      #data = {'email': email}
      #f = contactbyemail_form(data)
    return HttpResponse("OK")

# private pages

@cache_control(private=True)
def index(request):
  """Startup page after login"""
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  handle = suffixadd(request.user.username)
  return render_to_response('whois/index.html',
                            {'handle': handle,
                             'urichpass': URICHPASS,
                             'urichange': URICHANGE,
                             'uridomains': URIDOMAINS,
                             'urilogout': URILOGOUT})

@cache_control(private=True)
def chpass(request):
  """Contact password change"""
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  f = chpass_form()
  form = f.as_table()
  if request.method == "GET":
    return render_to_response('whois/chpass.html',
                              {'form': form, 'posturi': request.path})
  elif request.method == "POST":
    pass0 = request.POST.get('pass0', '')
    pass1 = request.POST.get('pass1', '')
    pass2 = request.POST.get('pass2', '')
    if pass1 != pass2:
      return render_to_response('whois/chpass.html',
                                {'form': form, 'posturi': request.path,
                                 'msg': "They don't match, try again"})
    if len(pass1) < 8:
      return render_to_response('whois/chpass.html',
                                {'form': form, 'posturi': request.path,
                                 'msg': "Password should be at least 8 chars"})

    ctlist = Contacts.objects.filter(handle=request.user.username)
    if len(ctlist) != 1:
      return HttpResponse("Internal Error")

    ct = ctlist[0]
    if ct.passwd != crypt.crypt(pass0, ct.passwd):
      return render_to_response('whois/chpass.html',
                                {'form': form, 'posturi': request.path,
                                 'msg': 'Current password is not correct.'})
    ct.passwd = crypt.crypt(pass1, _makesalt())
    ct.save()
    return render_to_response('whois/passchanged.html',
                              {'next': URIBASE})

@cache_control(private=True)
def domainlist(request):
  """Display domain list for current contact"""
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username
  c = Contacts.objects.get(handle=handle)
  dc = Whoisdomains.objects.filter(domaincontact__contact__exact=c.id).distinct().order_by('fqdn')
  return render_to_response('whois/domainlist.html',
                            {'posturi': request.path, 'doms': dc})

@cache_control(private=True)
def contactchange(request):
  """Contact modification page"""
  re_country = re.compile('^[a-zA-Z \t]+$')
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username
  if request.method == "GET":
    c = Contacts.objects.get(handle=handle)
    adlist = c.addr.split('\n')
    initial = { 'nh1': suffixadd(c.handle),
                'pn1': c.name,
                'em1': c.email,
                'ph1': c.phone,
                'fx1': c.fax }
    n = 1
    lastk = None
    for i in adlist:
      lastk = 'ad%d' % n
      initial[lastk] = i
      n += 1
    if lastk and lastk != 'ad6' and re_country.match(initial[lastk]):
      # If the last address line looks like a country, move it
      # to 'ad6'. This is a kludge, we'll get rid of it
      # when we add a dedicated country field in the database.
      initial['ad6'] = initial[lastk]
      del initial[lastk]
    form = contact_form(initial=initial)
  elif request.method == "POST":
    form = contact_form(request.POST)
    if form.is_valid():
      c = Contacts.objects.get(handle=handle)
      ad = []
      for i in '123456':
        k = 'ad%c' % i
        if form.cleaned_data[k] != '':
          ad.append(form.cleaned_data[k]) 
      changed = False
      if c.name != form.cleaned_data['pn1']:
        c.name = form.cleaned_data['pn1']
        changed = True
      if c.email != form.cleaned_data['em1']:
        c.email = form.cleaned_data['em1']
        changed = True
      for i in ['fx1', 'ph1']:
        if form.cleaned_data[i] == '':
          form.cleaned_data[i] = None
      if c.phone != form.cleaned_data['ph1']:
        c.phone = form.cleaned_data['ph1']
        changed = True
      if c.fax != form.cleaned_data['fx1']:
        c.fax = form.cleaned_data['fx1']
        changed = True
      if c.addr != '\n'.join(ad):
        c.addr = '\n'.join(ad)
        changed = True
      if changed:
        c.updated_on = None	# set to NOW() by the database
        c.updated_by = suffixadd(request.user.username)
        c.save()
      return render_to_response('whois/msgnext.html',
                                {'next': URIBASE,
                                 'msg': "Contact information changed successfully"})
    else:
      print "Not valid"
      print form.errors
  return render_to_response('whois/contactchange.html',
                            {'form': form, 'posturi': request.path})

def logout(request):
  """Logout page"""
  django.contrib.auth.logout(request)
  return HttpResponseRedirect(URILOGIN)
