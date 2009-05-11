# $Id$

import crypt
import datetime
import random
import re
import smtplib
import time

from autoreg.whois.db import HANDLESUFFIX,suffixstrip,suffixadd,Domain
from autoreg.arf.settings import URIBASE, URLBASE

import django.contrib.auth
from django.template.loader import get_template
from django.template import Context
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django import forms
from django.forms.widgets import PasswordInput
from django.views.decorators.cache import cache_control
from django.db import connection, transaction

from models import Whoisdomains,Contacts,Tokens

URILOGIN = URIBASE + 'login/'
URICHPASS = URIBASE + 'contact/chpass/'
URICHANGE = URIBASE + 'contact/change/'
URIDOMAINS = URIBASE + 'contact/domains/'
URIDOMAINEDIT = URIBASE + 'domain/edit/'
URIREGISTRANTEDIT = URIBASE + 'registrant/edit/'
URILOGOUT = URIBASE + 'logout/'
URICHANGEMAIL = URIBASE + 'contact/changemail/'
URIRESET = URIBASE + 'contact/reset/'
URLCHPASS = URLBASE + URICHPASS
URLCHANGEMAIL = URLBASE + URICHANGEMAIL
URLCONTACTVAL = URLBASE + URIBASE + 'contact/validate/%s/%s/'
URLRESET2 = URLBASE + URIBASE + 'contact/doreset/'
FROMADDR = 'noreply@eu.org'
RESET_TOKEN_HOURS_TTL = 24
EMAIL_TOKEN_HOURS_TTL = 72
RESET_TOKEN_TTL = RESET_TOKEN_HOURS_TTL*3600
EMAIL_TOKEN_TTL = EMAIL_TOKEN_HOURS_TTL*3600

uriset = {'uribase': URIBASE,
          'urichangemail': URICHANGEMAIL,
          'urichpass': URICHPASS,
          'urichange': URICHANGE,
          'uridomains': URIDOMAINS,
          'uridomainedit': URIDOMAINEDIT,
          'uriregistrantedit': URIREGISTRANTEDIT,
          'urireset': URIRESET,
          'urilogout': URILOGOUT}

# will be initialized by the first call to _countries_get()
countries = []

domcontact_choices = [('technical', 'technical'),
                      ('administrative', 'administrative'),
                      ('zone', 'zone')]

# for debug purposes
MAILBCC="pb@eu.org"

# chars allowed in passwords or reset/validation tokens
allowed_chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'

#
# Helper functions
#

def _pwcrypt(passwd):
  """Compute a MD5-based crypt(3) hash suitable for user authentication"""
  # Make a salt suitable for MD5-based crypt
  salt_chars = '0123456789abcdefghijklmnopqstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.'
  t = ''.join(random.SystemRandom().choice(salt_chars) for i in range(8))
  return crypt.crypt(passwd, '$1$' + t + '$')

def _render_to_mail(templatename, context, fromaddr, toaddrs):
  """Expand provided templatename and context, send the result
     by email to the indicated addresses."""
  t = get_template(templatename)
  msg = t.render(Context(context))
  headers, body = msg.split('\n\n', 1)
  msg = headers + '\n\n' + body.encode('utf-8').encode('quoted-printable')
  server = smtplib.SMTP()
  server.connect()
  server.sendmail(fromaddr, toaddrs + [ MAILBCC ], msg)
  server.quit()

def _uriset_render_to_response(template, vars):
  """Update vars with uriset then proceed with render_to_response()"""
  vars.update(uriset)
  return render_to_response(template, vars)

def _token_find(contact_id, action):
  """Find existing token(s)"""
  # Expire old tokens beforehand
  dbc = connection.cursor()
  dbc.execute('DELETE FROM arf_tokens WHERE expires < NOW()')
  return Tokens.objects.filter(contact_id=contact_id, action=action)

def _token_clear(contact_id, action):
  """Cleanup pre-existing token(s)"""
  _token_find(contact_id, action).delete()

def _token_set(contact_id, action, args=None, ttl=3600):
  """Create a token for the indicated action on the indicated contact"""
  sr = random.SystemRandom()
  token = ''.join(sr.choice(allowed_chars) for i in range(16))
  t = time.time()
  now = datetime.datetime.fromtimestamp(t)
  expires = datetime.datetime.fromtimestamp(t + ttl)
  tk = Tokens(contact_id=contact_id, date=now, expires=expires,
              token=token, action=action, args=args)
  tk.save()
  return token

# XXX: this should probably be moved to autoreg.whois.db
def _check_handle_domain_auth(handle, domain):
  """check handle is authorized on domain."""
  dom = Whoisdomains.objects.get(fqdn=domain.upper())
  cl = dom.domaincontact_set.filter(contact__handle__exact=handle)
  return len(cl) > 0

# XXX: this should probably be moved to autoreg.whois.db
def _countries_get():
  """Return a list of tuples containing ISO 3166 2-letter codes and names
     for countries."""
  if not countries:
    countries.append(('', 'Select one'))
    dbc = connection.cursor()
    dbc.execute('SELECT iso_id, name FROM iso3166_countries ORDER BY name')
    for cn in dbc.fetchall():
      countries.append(cn)
  return countries

# XXX: this should probably be moved to autoreg.whois.db
def _country_from_name(name):
  """Lookup country code from name"""
  nl = name.lower()
  for cn in countries:
    c, n = cn
    if n.lower() == nl:
      return c
  return None

#
# Forms
#

class contactbyemail_form(forms.Form):
  email = forms.EmailField(max_length=100)

class contactbyhandle_form(forms.Form):
  handle = forms.CharField(max_length=15, initial=HANDLESUFFIX, help_text='Your handle')

class contactchange_form(forms.Form):
  pn1 = forms.RegexField(max_length=60, label="Name", regex='^[a-zA-Z \.-]+\s+[a-zA-Z \.-]')
  em1 = forms.EmailField(max_length=64, label="E-mail")
  ad1 = forms.CharField(max_length=80, label="Organization")
  ad2 = forms.CharField(max_length=80, label="Address (line 1)")
  ad3 = forms.CharField(max_length=80, label="Address (line 2)", required=False)
  ad4 = forms.CharField(max_length=80, label="Address (line 3)", required=False)
  ad5 = forms.CharField(max_length=80, label="Address (line 4)", required=False)
  ad6 = forms.ChoiceField(initial='', label="Country (required)",
                          choices=_countries_get())
  ph1 = forms.RegexField(max_length=30, label="Phone Number", regex='^\+?[\d\s#\-\(\)\[\]\.]+$', required=False)
  fx1 = forms.RegexField(max_length=30, label="Fax Number", regex='^\+?[\d\s#\-\(\)\[\]\.]+$', required=False)

class contact_form(contactchange_form):
  p1 = forms.CharField(max_length=20, label='Password', required=False, widget=PasswordInput)
  p2 = forms.CharField(max_length=20, label='Confirm Password', required=False, widget=PasswordInput)
  policy = forms.BooleanField(label="I accept the Policy", required=True)

class registrant_form(forms.Form):
  # same as contactchange_form minus the email field
  pn1 = forms.RegexField(max_length=60, label="Name", regex='^[a-zA-Z \.-]+\s+[a-zA-Z \.-]')
  # disabled until we get rid of the RIPE model (unshared registrant records)
  #em1 = forms.EmailField(max_length=64, label="E-mail", required=False)
  ad1 = forms.CharField(max_length=80, label="Organization")
  ad2 = forms.CharField(max_length=80, label="Address (line 1)")
  ad3 = forms.CharField(max_length=80, label="Address (line 2)", required=False)
  ad4 = forms.CharField(max_length=80, label="Address (line 3)", required=False)
  ad5 = forms.CharField(max_length=80, label="Address (line 4)", required=False)
  ad6 = forms.ChoiceField(initial='', label="Country (required)",
                          choices=_countries_get())
  ph1 = forms.RegexField(max_length=30, label="Phone Number", regex='^\+?[\d\s#\-\(\)\[\]\.]+$', required=False)
  fx1 = forms.RegexField(max_length=30, label="Fax Number", regex='^\+?[\d\s#\-\(\)\[\]\.]+$', required=False)

class domcontact_form(forms.Form):
  handle = forms.CharField(max_length=10, initial=HANDLESUFFIX)
  contact_type = forms.ChoiceField(choices=domcontact_choices, label="type")

class contactlogin_form(forms.Form):
  handle = forms.CharField(max_length=15, initial=HANDLESUFFIX, help_text='Your handle')
  password = forms.CharField(max_length=30, help_text='Your password', widget=PasswordInput)

class resetpass_form(forms.Form):
  resettoken = forms.CharField(max_length=30, label='Reset Token')
  pass1 = forms.CharField(max_length=20, label='New Password', widget=PasswordInput)
  pass2 = forms.CharField(max_length=20, label='Confirm Password', widget=PasswordInput)

class changemail_form(forms.Form):
  token = forms.CharField(max_length=30)

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
    vars = {'form': form, 'posturi': request.path, 'next': next}
    return _uriset_render_to_response('whois/login.html', vars)
  elif request.method == "POST":
    next = request.POST.get('next', URIBASE)
    vars = {'next': next}
    if request.user.is_authenticated():
      #django.contrib.auth.logout(request)
      return HttpResponseRedirect(next)
      #return HttpResponse('OK')
    if not request.session.test_cookie_worked():
      vars['msg'] = "Please enable cookies"
      vars['form'] = contactlogin_form().as_table()
      return _uriset_render_to_response('whois/login.html', vars)
    else:
      #request.session.delete_test_cookie()
      pass
    handle = request.POST.get('handle', '').upper()
    password = request.POST.get('password', '')
    handle = suffixstrip(handle)

    vars = {'posturi': request.path, 'next': request.path,
            'form': contactlogin_form().as_table()}
    user = django.contrib.auth.authenticate(username=handle, password=password)
    if user is not None:
      if user.is_active:
        django.contrib.auth.login(request, user)
        return HttpResponseRedirect(next)
      else:
        vars['msg'] = "Sorry, your account has been disabled"
        return _uriset_render_to_response('whois/login.html', vars)
    else:
      vars['msg'] = "Your username and/or password is incorrect"
      return _uriset_render_to_response('whois/login.html', vars)

def makeresettoken(request):
  """Password reset step 1: send a reset token to the contact email address"""
  if request.method == "GET":
    f = contactbyhandle_form()
    form = f.as_table()
    return _uriset_render_to_response('whois/resetpass.html',
                                      {'form': form, 'posturi': request.path})
  elif request.method == "POST":
    handle = request.POST.get('handle', '').upper()
    fullhandle = handle
    handle = suffixstrip(handle)
    ctl = Contacts.objects.filter(handle=handle)
    if len(ctl) == 0:
      return _uriset_render_to_response('whois/contactnotfound.html',
                                        {'posturi': request.path,
                                         'ehandle': suffixadd(handle),
                                         'next': request.path})
    if len(ctl) != 1:
      return HttpResponse("Internal Error")
    ct = ctl[0]

    # create new token
    _token_clear(ct.id, action="pwreset")
    token = _token_set(ct.id, action="pwreset", ttl=RESET_TOKEN_TTL)

    _render_to_mail('whois/resetpass.mail',
                    { 'from': FROMADDR, 'to': ct.email,
                      'handle': fullhandle,
                      'reseturl': URLRESET2 + handle,
                      'token': token }, FROMADDR, [ ct.email ])
    return _uriset_render_to_response('whois/tokensent.html',
                                      {'ehandle': suffixadd(handle)})

def resetpass2(request, handle):
  """Password reset step 2:
     check provided reset token and force indicated password
     on the desginated contact."""
  f = resetpass_form()
  form = f.as_table()
  vars = {'form': form, 'posturi': request.path}
  if request.method == "GET":
    return _uriset_render_to_response('whois/resetpass2.html', vars)
  elif request.method == "POST":
    ctl = Contacts.objects.filter(handle=handle)
    if len(ctl) < 1:
      return _uriset_render_to_response('whois/resetpass2.html', vars)
    ct = ctl[0]
    pass1 = request.POST.get('pass1', 'A')
    pass2 = request.POST.get('pass2', 'B')
    if pass1 != pass2:
      vars['msg'] = "They don't match, try again"
      return _uriset_render_to_response('whois/resetpass2.html', vars)
    if len(pass1) < 8:
      vars['msg'] = "Password should be at least 8 chars"
      return _uriset_render_to_response('whois/resetpass2.html', vars)
    token = request.POST.get('resettoken', 'C')
    tkl = _token_find(ct.id, "pwreset")
    if len(tkl) > 1:
      return HttpResponse("Internal error")
    if len(tkl) == 0 or token != tkl[0].token:
      vars['msg'] = "Invalid reset token"
      return _uriset_render_to_response('whois/resetpass2.html', vars)
    tk = tkl[0]
    ct.passwd = _pwcrypt(pass1)
    ct.save()
    tk.delete()
    return _uriset_render_to_response('whois/passchanged.html',
                                      {'ehandle': suffixadd(handle)})

def contactcreate(request):
  """Contact creation page"""
  p_errors = []
  if request.method == "GET":
    form = contact_form()
  elif request.method == "POST":
    form = contact_form(request.POST)

    # validate password field by hand
    p1 = request.POST.get('p1', '')
    p2 = request.POST.get('p2', '')
    if p1 != p2:
      p_errors = ["Passwords don't match"]
    elif len(p1) < 8:
      p_errors = ["Password too short"]

    if form.is_valid() and not p_errors:
      #
      # Process contact creation
      #
      d = {}
      for i in ['pn', 'em', 'ph', 'fx']:
        v = form.cleaned_data.get(i + '1', None)
        if v != '':
          d[i] = [v]
      ad = []
      for i in ['ad1', 'ad2', 'ad3', 'ad4', 'ad5']:
        a = form.cleaned_data.get(i, None)
        if a is not None and a != '':
          ad.append(a)
      co = form.cleaned_data.get('ad6', None)
      if co is not None and co != '':
        d['co'] = [ co ]
      d['ad'] = ad
      d['ch'] = [(request.META.get('REMOTE_ADDR', 'REMOTE_ADDR_NOT_SET'), None)]

      from autoreg.whois.db import Person

      p = Person(connection.cursor(), passwd=_pwcrypt(p1), validate=False)
      if p.from_ripe(d):
        p.insert()
        valtoken = _token_set(p.cid, "contactval")
        handle = suffixstrip(p.gethandle())
        url = URLCONTACTVAL % (handle.upper(), valtoken)
        _render_to_mail('whois/contactcreate.mail',
                        {'url': url,
                         'whoisdata': p.__str__(),
                         'from': FROMADDR, 'to': d['em'][0]},
                        FROMADDR, [d['em'][0]])
        return _uriset_render_to_response('whois/msgnext.html',
                 {'msg': "Contact successfully created as %s. Please check instructions sent to %s to validate it." % (suffixadd(handle), d['em'][0])})
      # else: fall through
  return _uriset_render_to_response('whois/contactcreate.html',
                                    {'form': form, 'posturi': request.path,
                                     'p_errors': p_errors})

def contactvalidate(request, handle, valtoken):
  """Contact validation page"""
  if request.user.is_authenticated():
    django.contrib.auth.logout(request)

  # XXX: strange bug causes a SIGSEGV if we use valtoken from URL parsing
  # after a POST; instead we pass it as an hidden FORM variable,
  # hence the following two lines.
  if request.method == "POST":
    valtoken = request.POST.get('valtoken')

  msg = None
  ctl = Contacts.objects.filter(handle=handle)
  if len(ctl) != 1:
    msg = "Sorry, contact handle or validation token is not valid."
  else:
    tkl = _token_find(ctl[0].id, "contactval")
    if len(tkl) != 1 or tkl[0].token != valtoken:
      msg = "Sorry, contact handle or validation token is not valid."
  if msg:
    return _uriset_render_to_response('whois/msgnext.html', {'msg': msg})
  ct = ctl[0]
  if request.method == "GET":
    vars = {'handle': suffixadd(handle), 'email': ct.email,
            'valtoken': valtoken, 'posturi': request.path}
    return _uriset_render_to_response('whois/contactvalidate.html', vars)
  elif request.method == "POST":
    ct.validated_on = datetime.datetime.today()
    ct.save()
    tkl[0].delete()
    vars = {'msg': "Your contact handle is now valid."}
    return _uriset_render_to_response('whois/msgnext.html', vars)
  return HttpResponse("Internal error")

def contact(request, handle):
  """Contact display from handle"""
  c = Contacts.objects.get(handle=handle)
  vars = {'contact': c, 'address_list': c.addr.split('\n')[:-1]}
  return _uriset_render_to_response('whois/contact.html', vars)

def domain(request, fqdn):
  """Whois from domain FQDN"""
  f = fqdn.upper()
  try:
    dom = Whoisdomains.objects.get(fqdn=f)
  except Whoisdomains.DoesNotExist:
    dom = None
  if dom is None:
    vars = {'fqdn': fqdn}
    return _uriset_render_to_response('whois/domainnotfound.html', vars)
  cl = dom.domaincontact_set.all()
  vars = {'whoisdomain': dom, 'domaincontact_list': cl}
  return _uriset_render_to_response('whois/fqdn.html', vars)

# private pages

@cache_control(private=True)
def index(request):
  """Startup page after login"""
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  handle = suffixadd(request.user.username)
  vars = {'handle': handle}
  return _uriset_render_to_response('whois/index.html', vars)

@cache_control(private=True)
def chpass(request):
  """Contact password change"""
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username
  f = chpass_form()
  form = f.as_table()
  vars = {'form': form, 'posturi': request.path, 'handle': suffixadd(handle)}
  if request.method == "GET":
    return _uriset_render_to_response('whois/chpass.html', vars)
  elif request.method == "POST":
    pass0 = request.POST.get('pass0', '')
    pass1 = request.POST.get('pass1', '')
    pass2 = request.POST.get('pass2', '')
    if pass1 != pass2:
      vars['msg'] = "They don't match, try again"
      return _uriset_render_to_response('whois/chpass.html', vars)
    if len(pass1) < 8:
      vars['msg'] = "Password should be at least 8 chars"
      return _uriset_render_to_response('whois/chpass.html', vars)

    ctlist = Contacts.objects.filter(handle=handle)
    if len(ctlist) != 1:
      return HttpResponse("Internal Error")

    ct = ctlist[0]
    if ct.passwd != crypt.crypt(pass0, ct.passwd):
      vars['msg'] = "Current password is not correct"
      return _uriset_render_to_response('whois/chpass.html', vars)
    ct.passwd = _pwcrypt(pass1)
    ct.save()
    del vars['form']
    return _uriset_render_to_response('whois/passchanged.html', vars)

@cache_control(private=True)
def domainlist(request):
  """Display domain list for current contact"""
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username
  c = Contacts.objects.get(handle=handle)
  dc = Whoisdomains.objects.filter(domaincontact__contact__exact=c.id).distinct().order_by('fqdn')
  vars = {'posturi': request.path, 'handle': suffixadd(handle), 'doms': dc}
  return _uriset_render_to_response('whois/domainlist.html', vars)

@cache_control(private=True)
def contactchange(request, registrantdomain=None):
  """Contact or registrant modification page.
     If registrant, registrantdomain contains the associated domain FQDN.
  """
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username
  if registrantdomain:
    # check handle is authorized on domain
    if not _check_handle_domain_auth(handle, registrantdomain):
      # XXX
      return HttpResponse("Unauthorized")
    dom = Whoisdomains.objects.get(fqdn=registrantdomain)
    cl = dom.domaincontact_set.filter(contact_type__name='registrant')
    if len(cl) != 1:
      return HttpResponse("Internal error")
    ehandle = cl[0].contact.handle
  else:
    ehandle = handle

  vars = {'posturi': request.path, 'handle': suffixadd(handle)}
  if request.method == "GET":
    c = Contacts.objects.get(handle=ehandle)
    adlist = c.addr.rstrip().split('\n')
    initial = { 'pn1': c.name,
                'em1': c.email,
                'ph1': c.phone,
                'fx1': c.fax }
    n = 1
    lastk = None
    for i in adlist:
      lastk = 'ad%d' % n
      initial[lastk] = i
      n += 1
    if c.country is not None:
      initial['ad6'] = c.country
    elif lastk and lastk != 'ad6':
      co = _country_from_name(initial[lastk])
      if co:
        # For "legacy" contact records, if the last address line
        # looks like a country, convert it to an ISO country code
        # and move it to the 'ad6' field in the form.
        initial['ad6'] = co
        del initial[lastk]
    if registrantdomain:
      vars['form'] = registrant_form(initial=initial)
    else:
      vars['ehandle'] = suffixadd(ehandle)
      vars['form'] = contactchange_form(initial=initial)
    return _uriset_render_to_response('whois/contactchange.html', vars)
  elif request.method == "POST":
    if registrantdomain:
      form = registrant_form(request.POST)
    else:
      form = contactchange_form(request.POST)
    if form.is_valid():
      c = Contacts.objects.get(handle=ehandle)
      ad = []
      for i in '12345':
        k = 'ad%c' % i
        if form.cleaned_data[k] != '':
          ad.append(form.cleaned_data[k]) 
      changed = False
      emailchanged = False
      if c.name != form.cleaned_data['pn1']:
        c.name = form.cleaned_data['pn1']
        changed = True
      if ('em1' in form.cleaned_data
          and form.cleaned_data['em1'] != ''
          and c.email != form.cleaned_data['em1']):
        newemail = form.cleaned_data['em1']
        emailchanged = True
      for i in ['fx1', 'ph1']:
        if form.cleaned_data[i] == '':
          form.cleaned_data[i] = None
      if c.phone != form.cleaned_data['ph1']:
        c.phone = form.cleaned_data['ph1']
        changed = True
      if c.fax != form.cleaned_data['fx1']:
        c.fax = form.cleaned_data['fx1']
        changed = True
      if c.country != form.cleaned_data['ad6']:
        c.country = form.cleaned_data['ad6']
        changed = True
      if c.addr != '\n'.join(ad):
        c.addr = '\n'.join(ad)
        changed = True
      if changed:
        c.updated_on = None	# set to NOW() by the database
        c.updated_by = suffixadd(request.user.username)
        c.save()
      if emailchanged:
        _token_clear(c.id, "changemail")
        token = _token_set(c.id, "changemail", newemail, EMAIL_TOKEN_TTL)
        _render_to_mail('whois/changemail.mail',
                        {'from': FROMADDR, 'to': newemail,
                         'handle': suffixadd(ehandle),
                         'newemail': newemail,
                         'changemailurl': URLCHANGEMAIL,
                         'token': token }, FROMADDR, [ newemail ])
        return HttpResponseRedirect(URICHANGEMAIL)
      if registrantdomain:
        return HttpResponseRedirect(URIDOMAINEDIT + registrantdomain)
      else:
        vars['msg'] = "Contact information changed successfully"
        return _uriset_render_to_response('whois/msgnext.html', vars)
    else:
      vars['form'] = form
      return _uriset_render_to_response('whois/contactchange.html', vars)

@cache_control(private=True)
def changemail(request):
  """Email change step 2:
     check provided change email token and force indicated email
     on the designated contact."""
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username
  f = changemail_form()
  form = f.as_table()
  vars = {'form': form, 'posturi': request.path, 'handle': suffixadd(handle)}

  ctl = Contacts.objects.filter(handle=handle)
  if len(ctl) != 1:
    return HttpResponse("Internal error")
  ct = ctl[0]
  tkl = _token_find(ct.id, "changemail")
  if len(tkl) > 1:
    return HttpResponse("Internal error")
  if len(tkl) == 0:
      vars['msg'] = "Sorry, didn't find any waiting email address change."
      return _uriset_render_to_response('whois/changemail.html', vars)
  tk = tkl[0]

  vars['newemail'] = tk.args

  if request.method == "GET":
    return _uriset_render_to_response('whois/changemail.html', vars)
  elif request.method == "POST":
    token = request.POST.get('token', 'C')
    if token != tk.token:
      vars['msg'] = "Invalid token"
      return _uriset_render_to_response('whois/changemail.html', vars)
    newemail = tk.args
    ct.email = newemail
    ct.save()
    tk.delete()
    return _uriset_render_to_response('whois/emailchanged.html', vars)

@transaction.commit_on_success
@cache_control(private=True)
def domainedit(request, fqdn):
  """Edit domain contacts"""
  # list of shown and editable contact types
  typelist = ["administrative", "technical", "zone"]

  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username

  f = fqdn.upper()
  try:
    dom = Whoisdomains.objects.get(fqdn=f)
  except Whoisdomains.DoesNotExist:
    dom = None
  if dom is None:
    vars = {'fqdn': fqdn}
    return _uriset_render_to_response('whois/domainnotfound.html', vars)

  # check handle is authorized on domain
  if not _check_handle_domain_auth(handle, f):
    # XXX
    return HttpResponse("Unauthorized")

  dbdom = Domain(connection.cursor(), did=dom.id)
  dbdom.fetch()

  msg = None

  if request.method == "POST":
    if 'submit' in request.POST:
      contact_type = request.POST['contact_type']
      chandle = suffixstrip(request.POST['handle'])
      ctl = Contacts.objects.filter(handle=chandle)
      if len(ctl) == 0:
        msg = "Contact %s not found" % suffixadd(chandle)
      elif len(ctl) != 1:
        return HttpResponse("Internal error")
      else:
        cid = ctl[0].id
        if contact_type[0] not in 'atz':
          return HttpResponse("Internal error")
        code = contact_type[0] + 'c'
        if request.POST['submit'] == 'Delete':
          if cid in dbdom.d[code]:
            dbdom.d[code].remove(cid)
            dbdom.update()
            transaction.set_dirty()
            msg = "%s removed from %s contacts" % (chandle, contact_type)
          else:
            msg = "%s is not a contact" % suffixadd(chandle)
          # Fall through to updated form display
        elif request.POST['submit'] == 'Add':
          if cid not in dbdom.d[code]:
            dbdom.d[code].append(cid)
            dbdom.update()
            transaction.set_dirty()
            msg = "%s added to %s contacts" % (chandle, contact_type)
          else:
            msg = "%s is already a %s contact" % (chandle, contact_type)
          # Fall through to updated form display
    else:
      return HttpResponse("Internal error")
  elif request.method != "GET":
    return HttpResponse("Internal error")

  # handle GET or end of POST

  # get contact list
  cl = dom.domaincontact_set.order_by('contact_type', 'contact__handle')
  formlist = []
  for c in cl:
    ct = c.contact_type.name
    if ct in typelist:
      cthandle = c.contact.handle
      formlist.append({'contact_type': ct,
                       'handle': suffixadd(cthandle),
                       'posturi': request.path })

  vars = {'whoisdomain': dom, 'domaincontact_list': cl,
          'msg': msg,
          'formlist': formlist,
          'whoisdisplay': unicode(dbdom),
          'addform': {'posturi': request.path,
                      'domcontact_form': domcontact_form().as_table()}}
  return _uriset_render_to_response('whois/domainedit.html', vars)

def logout(request):
  """Logout page"""
  django.contrib.auth.logout(request)
  return HttpResponseRedirect(URILOGIN)
