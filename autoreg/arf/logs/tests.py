from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


from django.db import connection
from django.test import TestCase, Client


from autoreg.util import pwcrypt
from autoreg.whois.db import Person, suffixadd
from ..whois.models import Admins, Contacts


class LogTest(TestCase):
  def setUp(self):
    cursor = connection.cursor()
    # Minimal test account
    d = {'pn': ['Test Person'], 'em': ['foobaremail@email.bla'],
         'ad': ['test address', 'line2', 'line3'],
         'co': ['FR'], 'cn': ('France',),
         'pr': [True], 'ch': [('::1', None)]}

    self.pw = 'aaabbbcccddd'
    p = Person(cursor, passwd=pwcrypt(self.pw),
               validate=True)
    pr = p.from_ripe(d)
    self.assertTrue(pr)
    p.insert()
    self.handle = p.gethandle()

    # Admin account
    d3 = {'pn': ['Admin Account'], 'em': ['foobaremail3@email.bla'],
          'ad': ['test address 3', 'line2', 'line3'],
          'co': ['FR'], 'cn': ('France',),
          'pr': [True], 'ch': [('::1', None)]}
    self.pw3 = 'aaabbbcccddd3'
    p3 = Person(cursor, passwd=pwcrypt(self.pw3),
                validate=True)
    pr = p3.from_ripe(d3)
    self.assertTrue(pr)
    p3.insert()
    self.assertEqual(suffixadd('AA1'), p3.gethandle())
    a = Admins(login='AA1', contact=Contacts.objects.get(handle='AA1'))
    a.save()
    self.admin_handle = p3.gethandle()

    self.c = Client()

  def test_log_post(self):
    r = self.c.post('/en/log')
    self.assertEqual(400, r.status_code)

  def test_log_anon(self):
    r = self.c.get('/en/log')
    self.assertEqual(403, r.status_code)

  def test_log_auth(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/log')
    self.assertEqual(403, r.status_code)

  def test_log_admin(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/log')
    self.assertEqual(200, r.status_code)
