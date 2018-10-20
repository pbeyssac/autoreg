from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import re


from django.core import mail
from django.db import connection
from django.test import TestCase, Client

from autoreg.whois.db import Person, suffixadd, suffixstrip
from ..webdns.models import Domains, Zones
from .models import Admins, Contacts, DomainContact, Whoisdomains
from . import token


class AccountTest(TestCase):
  def setUp(self):
    cursor = connection.cursor()

    # Minimal test account
    self.handle = suffixadd('TP1')
    self.pw = 'aaabbbcccddd'

    # Test account with a long handle
    self.long_handle = 'ZZ1111'
    self.pw2 = 'aaabbbcccddd2'

    # Admin account
    self.admin_handle = suffixadd('AA1')
    self.pw3 = 'aaabbbcccddd3'
    a = Admins.objects.get(login='AA1')

    # Unvalidated account
    self.unval_handle = suffixadd('UA1')

    # Registrant
    d = {'pn': ['Test Registrant'], 'em': [None],
         'ad': ['test address', 'line2', 'line3'],
         'co': ['FR'], 'cn': ('France',),
         'pr': [True], 'ch': [('::1', None)]}
    p4 = Person(cursor, validate=True)
    pr4 = p4.from_ripe(d)
    self.assertTrue(pr4)
    p4.insert()
    self.handle_registrant = p4.gethandle()

    self.domain = 'foobar.eu.org'
    w = Whoisdomains(fqdn=self.domain.upper())
    w.save()
    DomainContact(whoisdomain=w, contact=Contacts.objects.get(handle='TP1'), contact_type_id=1).save()
    DomainContact(whoisdomain=w, contact=Contacts.objects.get(handle=suffixstrip(self.handle_registrant)), contact_type_id=4).save()

    z = Zones.objects.get(name='EU.ORG')
    self.zone_id = z.id

    Domains(name='FOOBAR', zone=z, created_by=a, updated_by=a).save()

    w2 = Whoisdomains(fqdn='FOOBAR2.EU.ORG')
    w2.save()
    Domains(name='FOOBAR2', zone=z).save()

    self.c = Client()

  def test_login(self):
    # Test login form
    r = self.c.get('/login/')
    self.assertEqual(302, r.status_code)
    r = self.c.get('/en/login/')
    self.assertEqual(200, r.status_code)
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': 'wrongpassword'})
    self.assertEqual(200, r.status_code)
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': self.pw})
    self.assertEqual(302, r.status_code)

  def test_login_logout(self):
    # Do a Django login
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))

    r = self.c.post('/en/logout/')
    self.assertEqual(302, r.status_code)

    r = self.c.post('/en/logout/')
    self.assertEqual(302, r.status_code)

  def test_contactchange_ko(self):
    r = self.c.get('/en/contact/change/')
    self.assertEqual(302, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/login/?next=/en/contact/change/', r['Location'])
  def test_contactchangemail_ko(self):
    r = self.c.get('/en/contact/changemail/')
    self.assertEqual(302, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/login/?next=/en/contact/changemail/', r['Location'])
  def test_contactchpass_ko(self):
    r = self.c.get('/en/contact/chpass/')
    self.assertEqual(302, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/login/?next=/en/contact/chpass/', r['Location'])
  def test_domainlist_ko(self):
    r = self.c.get('/en/domain/list/' + suffixstrip(self.handle))
    self.assertEqual(302, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/login/?next=/en/domain/list/' + suffixstrip(self.handle), r['Location'])
  def test_domain_edit_confirm_ko_1(self):
    r = self.c.get('/en/domain/edit/confirm/' + self.domain)
    self.assertEqual(301, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/domain/edit/confirm/' + self.domain + '/', r['Location'])
  def test_domain_edit_confirm_ko_2(self):
    r = self.c.get('/en/domain/edit/confirm/' + self.domain + '/')
    self.assertEqual(405, r.status_code)
    self.assertEqual(b'', r.content)
  def test_domain_edit_confirm_ko_3(self):
    r = self.c.post('/en/domain/edit/confirm/' + self.domain)
    self.assertEqual(301, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/domain/edit/confirm/' + self.domain + '/', r['Location'])

  def test_contactchange_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/contact/change/')
    self.assertEqual(200, r.status_code)
  def test_contactchangemail_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/contact/changemail/')
    self.assertEqual(200, r.status_code)
  def test_contactchpass_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/contact/chpass/')
    self.assertEqual(200, r.status_code)
  def test_home_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/')
    self.assertEqual(200, r.status_code)

  def test_domainlist_perm(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/domain/list/' + suffixstrip(self.handle))
    self.assertEqual(403, r.status_code)

  def test_domain_edit_1(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/domain/edit/' + self.domain)
    self.assertEqual(301, r.status_code)
    self.assertEqual('/en/domain/edit/' + self.domain + '/', r['Location'])
  def test_domain_edit_2(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/domain/edit/' + self.domain + '/')
    self.assertEqual(200, r.status_code)
  def test_domain_edit_confirm_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))

    fields = {'contact_type': 'technical'}
    r = self.c.post('/en/domain/edit/confirm/' + self.domain + '/', fields)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/domain/edit/' + self.domain + '/', r['Location'])

    fields = {'contact_type': 'technical', 'handle': self.handle}
    r = self.c.post('/en/domain/edit/confirm/' + self.domain + '/', fields)
    self.assertEqual(200, r.status_code)

  def test_contact_change_post(self):
    """Test full email change procedure"""
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = { 'pn1': 'New Name',
               'em1': 'newemail@foobar.eu.org',
               'ad1': 'New address',
               'ad2': 'New city',
               'ad6': 'ES',
               'private': True }
    r = self.c.post('/en/contact/change/', fields)
    self.assertEqual(302, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertEqual('/en/contact/changemail/', r['Location'])
    self.assertEqual(len(mail.outbox), 1)
    msg = str(mail.outbox[0].message())
    re_token = re.compile('Enter the following validation token: ([a-zA-Z0-9]{16,16})$',
                          re.MULTILINE)
    m = re_token.search(msg)
    self.assertNotEqual(None, m)
    mtoken = m.groups()[0]

    r = self.c.get('/en/contact/changemail/')
    self.assertEqual(200, r.status_code)
    re_email = re.compile('Please look for email sent to <strong>([^<]+@[^<]+)<')
    m = re_email.search(str(r.content))
    self.assertNotEqual(None, m)
    self.assertEqual('newemail@foobar.eu.org', m.groups()[0])

    fields = {'token': 'badtoken'}
    r = self.c.post('/en/contact/changemail/', fields)
    self.assertTrue('Invalid token' in str(r.content))
    self.assertEqual(200, r.status_code)

    fields = {'token': mtoken}
    r = self.c.post('/en/contact/changemail/', fields)
    self.assertFalse('Invalid token' in str(r.content))
    self.assertEqual(200, r.status_code)

    re_ok = re.compile('set to <span class="email">([^<]+@[^<]+)<')
    m = re_ok.search(str(r.content))
    self.assertNotEqual(None, m)
    self.assertEqual('newemail@foobar.eu.org', m.groups()[0])

    ct = Contacts.objects.get(handle=suffixstrip(self.handle))
    self.assertEqual('newemail@foobar.eu.org', ct.email)
    self.assertEqual(0, len(token.token_find(ct.id, "changemail")))

  def test_get_del_405_anon(self):
    r = self.c.get('/en/domain/del/' + self.domain + '/')
    self.assertEqual(405, r.status_code)
  def test_del_405_logged(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/domain/del/' + self.domain + '/')
    self.assertEqual(405, r.status_code)
  def test_del_upper(self):
    r = self.c.get('/en/domain/del/' + self.domain.upper() + '/')
    self.assertEqual(404, r.status_code)
  def test_post_del_anon(self):
    r = self.c.post('/en/domain/del/' + self.domain + '/')
    self.assertEqual(302, r.status_code)
  def test_del_301(self):
    r = self.c.post('/en/domain/del/' + self.domain)
    self.assertEqual(301, r.status_code)
    self.assertEqual('/en/domain/del/' + self.domain + '/', r['Location'])

  def test_get_undel_anon_(self):
    r = self.c.get('/en/domain/undel/' + self.domain + '/')
    self.assertEqual(405, r.status_code)
  def test_get_undel_405_logged(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/domain/undel/' + self.domain + '/')
    self.assertEqual(405, r.status_code)
  def test_get_undel_upper(self):
    r = self.c.get('/en/domain/undel/' + self.domain.upper() + '/')
    self.assertEqual(404, r.status_code)
  def test_undel_anon(self):
    r = self.c.post('/en/domain/undel/' + self.domain + '/')
    self.assertEqual(302, r.status_code)
  def test_undel_301(self):
    r = self.c.post('/en/domain/undel/' + self.domain)
    self.assertEqual(301, r.status_code)
    self.assertEqual('/en/domain/undel/' + self.domain + '/', r['Location'])

  def test_del_undel(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.post('/en/domain/del/' + self.domain + '/')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/domain/edit/' + self.domain + '/', r['Location'])
    dl = Domains.objects.filter(name=self.domain.split('.')[0], zone_id=self.zone_id)
    self.assertEqual(0, len(dl))
    wdl = Whoisdomains.objects.filter(fqdn=self.domain.upper())
    self.assertEqual(1, len(wdl))
    r = self.c.post('/en/domain/undel/' + self.domain + '/')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/domain/edit/' + self.domain + '/', r['Location'])

  def test_registrant(self):
    r = self.c.get('/en/registrant/edit/' + self.domain.lower() + '/')
    self.assertEqual(302, r.status_code)
  def test_contact_bydom(self):
    r = self.c.get('/en/contact/bydom')
    self.assertEqual(200, r.status_code)
  def test_contact_bydom_domain(self):
    r = self.c.get('/en/contact/bydom/' + self.domain)
    self.assertEqual(200, r.status_code)

  def test_public_logout(self):
    r = self.c.post('/en/logout/')
    self.assertEqual(302, r.status_code)
  def test_public_contact_create(self):
    r = self.c.get('/en/contact/create/')
    self.assertEqual(200, r.status_code)
  def test_public_contact_reset(self):
    r = self.c.get('/en/contact/reset/')
    self.assertEqual(200, r.status_code)
  def test_public_contact_reset_handle(self):
    r = self.c.get('/en/contact/reset/' + suffixstrip(self.handle))
    self.assertEqual(200, r.status_code)
  def test_public_contact_doreset_handle(self):
    r = self.c.get('/en/contact/doreset/' + suffixstrip(self.handle))
    self.assertEqual(301, r.status_code)
    self.assertEqual('/en/contact/doreset/TP1/', r['Location'])
  def test_public_contact_validate_handle(self):
    r = self.c.get('/en/contact/validate/' + suffixstrip(self.handle) + '/aaaaa')
    self.assertEqual(301, r.status_code)

  def test_contact_reset_contact(self):
    r = self.c.get('/en/contact/reset/' + suffixstrip(self.handle))
    self.assertEqual(200, r.status_code)
    r = self.c.post('/en/contact/reset/', {'handle': self.handle})
    self.assertEqual(len(mail.outbox), 1)
    msg = str(mail.outbox[0].message())
    regex = """^Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: password reset for EU.org contact TP1-FREE
From: noreply@eu.org
To: foobaremail@email.bla
Date: .*
Message-ID: <[^>]+@[^>]+>

Hello,

Please ignore this request if you didn't initiate it.
Someone may be trying to steal your account.

Following a request on our web site from 127.0.0.1,
here is how to set a new password on your EU.org contact
record identified as TP1-FREE:

- Connect to http://testserver/en/contact/doreset/TP1/
- Enter the following reset code: ([a-zA-Z0-9]{16,16})
- Enter the desired new password
- Then validate.


Best Regards,
The EU.org team
$"""

    mailre = re.compile(regex)
    m = mailre.match(msg)
    self.assertNotEqual(None, m)
    token = m.groups()[0]

    fields = {'pass1': 'AAAAAAA1', 'pass2': 'AAAAAAA2', 'resettoken': token}
    r = self.c.post('/en/contact/doreset/' + suffixstrip(self.handle) + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertFalse('Password changed' in str(r.content))

    fields = {'pass1': 'A', 'pass2': 'A', 'resettoken': token}
    r = self.c.post('/en/contact/doreset/' + suffixstrip(self.handle) + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertFalse('Password changed' in str(r.content))

    fields = {'pass1': 'AAAAAAAA', 'pass2': 'AAAAAAAA', 'resettoken': 'wrongtoken'}
    r = self.c.post('/en/contact/doreset/' + suffixstrip(self.handle) + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertFalse('Password changed' in str(r.content))

    fields = {'pass1': 'AAAAAAAA', 'pass2': 'AAAAAAAA', 'resettoken': token}
    r = self.c.post('/en/contact/doreset/' + suffixstrip(self.handle) + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Password changed' in str(r.content))

    # Test Django login with the new password
    self.assertTrue(self.c.login(username=self.handle, password='AAAAAAAA'))

  def test_contact_reset_registrant_1(self):
    r = self.c.get('/en/contact/reset/' + suffixstrip(self.handle_registrant))
    self.assertEqual(200, r.status_code)
    self.assertEqual(len(mail.outbox), 0)
  def test_contact_reset_registrant_2(self):
    r = self.c.post('/en/contact/reset/', {'handle': self.handle_registrant})
    self.assertEqual(200, r.status_code)
    self.assertEqual(len(mail.outbox), 0)

  def test_contact_create(self):
    fields = {
      'p1': 'BBBBBBBB', 'p2': 'BBBBBBBB',
      'pn1': 'Test Contact Create',
      'em1': 'newaddr@foo.bar',
      'ad1': 'My address line 1',
      'ad2': 'My address line 2',
      'ad6': 'FR',
      'private': 'A' }

    r = self.c.post('/en/contact/create/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('error">\\n    <label for="id_policy">I have read' in str(r.content))

    fields['policy'] = 'A'
    r = self.c.post('/en/contact/create/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Contact successfully created as TCC1' in str(r.content))

    self.assertEqual(len(mail.outbox), 1)
    msg = str(mail.outbox[0].message())

    token_re = re.compile('/validate/TCC1/([A-Za-z0-9]+)/')
    m = token_re.search(msg)
    self.assertTrue(True, m != None)
    token = m.groups()[0]

    c = Contacts.objects.get(handle='TCC1')
    self.assertEqual(None, c.validated_on)

    r = self.c.get('/en/contact/validate/TCC1/' + token + '/')
    self.assertEqual(200, r.status_code)

    # Validate via POST
    fields = {'handle': suffixadd('TCC1'), 'valtoken': token}
    r = self.c.post('/en/contact/validate/TCC1/' + token + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Your contact handle is now valid' in str(r.content))

    c = Contacts.objects.get(handle='TCC1')
    self.assertNotEqual(None, c.validated_on)

    # Test Django login with the new password
    self.assertTrue(self.c.login(username='TCC1', password='BBBBBBBB'))

  def test_contact_validate_post_bad(self):
    r = self.c.post('/en/contact/validate/TP1/wrong/', {})
    self.assertEqual(200, r.status_code)
    self.assertFalse('Your contact handle is now valid' in str(r.content))
  def test_contact_validate_post_bad2(self):
    r = self.c.post('/en/contact/validate/TCC1/wrong/', {})
    self.assertEqual(200, r.status_code)
    self.assertFalse('Your contact handle is now valid' in str(r.content))
  def test_contact_validate_get_bad(self):
    r = self.c.get('/en/contact/validate/TP1/wrong/')
    self.assertEqual(200, r.status_code)
  def test_contact_validate_get_bad2(self):
    r = self.c.get('/en/contact/validate/TCC1/wrong/')
    self.assertEqual(200, r.status_code)

  def test_domainedit_handle_len(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = { 'contact_type': 'technical',
               'handle': suffixadd('TP1'),
               'submita': '' }
    r = self.c.post('/en/domain/edit/' + self.domain + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('TP1' in str(r.content))
    self.assertFalse('ZZ1111' in str(r.content))

    fields['handle'] = suffixadd('ZZ1111')
    r = self.c.post('/en/domain/edit/' + self.domain + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('ZZ1111' in str(r.content))

  def test_domainedit_unval(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = { 'contact_type': 'technical',
               'handle': self.unval_handle,
               'submita': '' }
    r = self.c.post('/en/domain/edit/' + self.domain + '/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue(self.unval_handle + ' must be valid' in str(r.content))
    n = DomainContact.objects.filter(whoisdomain__fqdn=self.domain, contact__handle=suffixstrip(self.unval_handle)).count()
    self.assertEqual(0, n)

  def test_domainedit_nologin(self):
    r = self.c.post('/en/domain/edit/' + self.domain + '/', {})
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/domain/edit/'+self.domain+'/', r['Location'])

  def test_domainedit_403(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.post('/en/domain/edit/foobar2.eu.org/', {})
    self.assertEqual(403, r.status_code)

  def test_contact_chpass_302(self):
    r = self.c.get('/en/contact/chpass/')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/contact/chpass/', r['Location'])

  def test_contact_chpass_get(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/contact/chpass/')
    self.assertEqual(200, r.status_code)

  def test_contact_chpass_post_badpw0(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = {'pass0': 'AAAA', 'pass1': 'CCCCCCCC', 'pass2': 'CCCCCCCC'}
    r = self.c.post('/en/contact/chpass/', fields)
    self.assertEqual(200, r.status_code)
    self.assertFalse('Password changed' in str(r.content))

  def test_contact_chpass_post_badpw1(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = {'pass0': 'AAAA', 'pass1': 'CCCCCCCC', 'pass2': 'CCCCCCCD'}
    r = self.c.post('/en/contact/chpass/', fields)
    self.assertEqual(200, r.status_code)
    self.assertFalse('Password changed' in str(r.content))

  def test_contact_chpass_post_badpw2(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = {'pass0': 'AAAA', 'pass1': 'CCCCCC', 'pass2': 'CCCCCC'}
    r = self.c.post('/en/contact/chpass/', fields)
    self.assertEqual(200, r.status_code)
    self.assertFalse('Password changed' in str(r.content))

  def test_contact_chpass_post_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    fields = {'pass0': self.pw, 'pass1': 'CCCCCCCC', 'pass2': 'CCCCCCCC'}
    r = self.c.post('/en/contact/chpass/', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Password changed' in str(r.content))

    self.c.logout()
    # Test login fails with the old password
    self.assertFalse(self.c.login(username=self.handle, password=self.pw))
    # Test login works with the new password
    self.assertTrue(self.c.login(username=self.handle, password='CCCCCCCC'))
