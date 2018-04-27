from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from django.db import connection
from django.test import TestCase, Client

from autoreg.whois.db import Person, suffixadd, suffixstrip
from . import views


class AccountTest(TestCase):
  def setUp(self):
    # Minimal test account
    d = {'pn': ['Test Person'], 'em': ['foobaremail@email.bla'],
         'ad': ['test address', 'line2', 'line3'],
         'co': ['FR'], 'cn': ('France',),
         'pr': [True], 'ch': [('::1', None)]}

    self.pw = 'aaabbbcccddd'
    p = Person(connection.cursor(), passwd=views._pwcrypt(self.pw),
               validate=True)
    pr = p.from_ripe(d)

    #print(p.get_msgs())

    self.assertTrue(pr)

    p.insert()
    self.handle = p.gethandle()

    self.domain = 'foobar.eu.org'
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
