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
from . import views


class AccountTest(TestCase):
  def setUp(self):
    cursor = connection.cursor()
    # Minimal test account
    d = {'pn': ['Test Person'], 'em': ['foobaremail@email.bla'],
         'ad': ['test address', 'line2', 'line3'],
         'co': ['FR'], 'cn': ('France',),
         'pr': [True], 'ch': [('::1', None)]}

    self.pw = 'aaabbbcccddd'
    p = Person(cursor, passwd=views._pwcrypt(self.pw),
               validate=True)
    pr = p.from_ripe(d)
    self.assertTrue(pr)
    p.insert()
    self.handle = p.gethandle()

    # Test account with a long handle
    d2 = {'nh': [suffixadd('ZZ1111')],
          'pn': ['Test Person2'], 'em': ['foobaremail2@email.bla'],
          'ad': ['test address 2', 'line2', 'line3'],
          'co': ['FR'], 'cn': ('France',),
          'pr': [True], 'ch': [('::1', None)]}
    self.pw2 = 'aaabbbcccddd2'
    p2 = Person(cursor, passwd=views._pwcrypt(self.pw2),
                validate=True)
    pr = p2.from_ripe(d2)
    self.assertTrue(pr)
    p2.insert()
    self.assertEqual(suffixadd('ZZ1111'), p2.gethandle())

    # Admin account
    d3 = {'pn': ['Admin Account'], 'em': ['foobaremail3@email.bla'],
          'ad': ['test address 3', 'line2', 'line3'],
          'co': ['FR'], 'cn': ('France',),
          'pr': [True], 'ch': [('::1', None)]}
    self.pw3 = 'aaabbbcccddd3'
    p3 = Person(cursor, passwd=views._pwcrypt(self.pw3),
                validate=True)
    pr = p3.from_ripe(d3)
    self.assertTrue(pr)
    p3.insert()
    self.assertEqual(suffixadd('AA1'), p3.gethandle())
    a = Admins(login='AA1', contact=Contacts.objects.get(handle='AA1'))
    a.save()
    self.admin_handle = p3.gethandle()

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

    z = Zones(name='EU.ORG', minlen=2, maxlen=64, ttl=3600,
              updateserial=False, soaserial=1, soarefresh=3600,
              soaretry=3600, soaexpires=3600, soaminimum=3600,
              soaprimary=3600, soaemail='nobody.eu.org')
    z.save()
    Domains(name='FOOBAR', zone=z).save()

    self.c = Client()

  def test_login_logout(self):
    # Test login form
    r = self.c.get('/login/')
    self.assertEqual(302, r.status_code)
    r = self.c.get('/en/login/')
    self.assertEqual(200, r.status_code)
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': 'wrongpassword'})
    self.assertEqual(200, r.status_code)
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': self.pw})
    self.assertEqual(302, r.status_code)

    # Do a Django login
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))

    r = self.c.post('/en/logout/')
    self.assertEqual(302, r.status_code)

    r = self.c.post('/en/logout/')
    self.assertEqual(302, r.status_code)

  def test_access_ko(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/contact/change/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/changemail/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/chpass/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/')
    self.assertEqual(200, r.status_code)
  def test_access_ok(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/contact/change/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/changemail/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/chpass/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/')
    self.assertEqual(200, r.status_code)
    # r = self.c.get('/en/domain/list/' + self.handle)
    # self.assertEqual(200, r.status_code)

    r = self.c.get('/en/domain/edit/' + self.domain)
    self.assertEqual(301, r.status_code)
    r = self.c.get('/en/domain/edit/' + self.domain + '/')
    self.assertEqual(200, r.status_code)
    #r = self.c.get('/en/domain/edit/confirm/' + self.domain)
    #self.assertEqual(200, r.status_code)
  def test_del_undel(self):
    #r = self.c.get('/en/domain/del/' + self.domain + '/')
    #self.assertEqual(200, r.status_code)
    r = self.c.get('/en/domain/undel/' + self.domain)
    self.assertEqual(301, r.status_code)
    r = self.c.get('/en/domain/undel/' + self.domain.lower())
    self.assertEqual(301, r.status_code)
  def test_registrant(self):
    r = self.c.get('/en/registrant/edit/' + self.domain.lower() + '/')
    self.assertEqual(302, r.status_code)
  def test_contact_bydom(self):
    r = self.c.get('/en/contact/bydom')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/bydom/' + self.domain)
    self.assertEqual(200, r.status_code)

  def test_public(self):
    r = self.c.post('/en/logout/')
    self.assertEqual(302, r.status_code)
    r = self.c.get('/en/contact/create/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/reset/')
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/reset/' + suffixstrip(self.handle))
    self.assertEqual(200, r.status_code)
    r = self.c.get('/en/contact/doreset/' + suffixstrip(self.handle))
    self.assertEqual(301, r.status_code)
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
- Enter the following reset code: [a-zA-Z0-9]{16,16}
- Enter the desired new password
- Then validate.


Best Regards,
The EU.org team
$"""

    mailre = re.compile(regex)
    self.assertNotEqual(None, mailre.match(msg))

  def test_contact_reset_registrant(self):
    r = self.c.get('/en/contact/reset/' + suffixstrip(self.handle_registrant))
    self.assertEqual(200, r.status_code)
    self.assertEqual(len(mail.outbox), 0)
    r = self.c.post('/en/contact/reset/', {'handle': self.handle_registrant})
    self.assertEqual(200, r.status_code)
    self.assertEqual(len(mail.outbox), 0)

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
