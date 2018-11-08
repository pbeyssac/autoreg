from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


from django.test import TestCase, Client


from autoreg.whois.db import suffixadd


class LogTest(TestCase):
  def setUp(self):
    # Minimal test account
    self.handle = suffixadd('TP1')
    self.pw = 'aaabbbcccddd'

    # Admin account
    self.admin_handle = suffixadd('AA1')
    self.pw3 = 'aaabbbcccddd3'

    self.c = Client()

  def test_log_post(self):
    r = self.c.post('/en/log')
    self.assertEqual(400, r.status_code)

  def test_log_anon(self):
    r = self.c.get('/en/log')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/log', r['Location'])

  def test_log_auth(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/log')
    self.assertEqual(403, r.status_code)

  def test_log_admin(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/log')
    self.assertEqual(200, r.status_code)
