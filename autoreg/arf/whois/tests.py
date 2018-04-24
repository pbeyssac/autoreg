from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from django.db import connection
from django.test import TestCase, Client

from autoreg.whois.db import Person, suffixadd
from . import views


class AccountTest(TestCase):
  def test_create(self):
    # Minimal test account
    d = {'pn': ['Test Person'], 'em': ['foobaremail@email.bla'],
         'ad': ['test address', 'line2', 'line3'],
         'co': ['FR'], 'cn': ('France',),
         'pr': [True], 'ch': [('::1', None)]}

    pw = 'aaabbbcccddd'
    p = Person(connection.cursor(), passwd=views._pwcrypt(pw),
               validate=True)
    pr = p.from_ripe(d)

    print(p.get_msgs())

    self.assertTrue(pr)

    p.insert()
    handle = p.gethandle()

    c = Client()

    # Test login form
    r = c.get('/login/')
    self.assertEqual(302, r.status_code)
    r = c.get('/en/login/')
    self.assertEqual(200, r.status_code)
    r = c.post('/en/login/', {'handle': handle, 'password': 'wrongpassword'})
    self.assertEqual(200, r.status_code)
    r = c.post('/en/login/', {'handle': handle, 'password': pw})
    self.assertEqual(302, r.status_code)

    # Do a Django login
    self.assertTrue(c.login(username=handle, password=pw))

    r = c.post('/en/logout/')
    self.assertEqual(302, r.status_code)

    r = c.post('/en/logout/')
    self.assertEqual(302, r.status_code)
