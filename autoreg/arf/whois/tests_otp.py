from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import re


import pyotp


from django.core import mail
from django.db import connection
from django.test import TestCase, Client


from autoreg.util import pwcrypt
from autoreg.whois.db import Person, suffixadd, suffixstrip
from . import otp, views


#
# Tests with a unconfigured account
#
class OtpTestMisc(TestCase):
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

    self.c = Client()

  def test_2fa_home_post(self):
    r = self.c.post('/en/2fa/')
    self.assertEqual(405, r.status_code)
  def test_2fa_home_anon(self):
    r = self.c.get('/en/2fa/')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/2fa/', r['Location'])
  def test_2fa_home(self):
    # Do a Django login
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/2fa/')
    self.assertEqual(200, r.status_code)
    self.assertTrue('not set' in str(r.content))

  def test_2fa_set1_post(self):
    r = self.c.post('/en/2fa/set/1')
    self.assertEqual(405, r.status_code)
  def test_2fa_set1_anon(self):
    r = self.c.get('/en/2fa/set/1')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/2fa/set/1', r['Location'])
  def test_2fa_set2_post_anon(self):
    r = self.c.post('/en/2fa/set/2')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/2fa/set/2', r['Location'])
  def test_2fa_set2_anon(self):
    r = self.c.get('/en/2fa/set/2')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/2fa/set/2', r['Location'])
  def test_2fa_clear_post(self):
    r = self.c.post('/en/2fa/clear')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/2fa/clear', r['Location'])
  def test_2fa_clear_anon(self):
    r = self.c.get('/en/2fa/clear')
    self.assertEqual(405, r.status_code)
  def test_2fa_newrecovery_post(self):
    r = self.c.post('/en/2fa/newrecovery')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/2fa/newrecovery', r['Location'])
  def test_2fa_newrecovery_anon(self):
    r = self.c.get('/en/2fa/newrecovery')
    self.assertEqual(405, r.status_code)

  def test_2fa_set_full(self):
    """Test a full 2FA setup procedure"""
    # Do a Django login
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/2fa/set/1')
    self.assertEqual(200, r.status_code)

    # check full list of codes
    re_codes = re.compile('((?:<li>\d{8,8}</li> ){10,10})')
    m = re_codes.search(str(r.content))
    self.assertNotEqual(None, m)

    # extract all codes
    re_code = re.compile('<li>(\d{8,8})</li>')
    code_list = [m.groups()[0] for m in re_code.finditer(str(r.content))]
    self.assertEqual(10, len(code_list))

    # check the state is correctly recorded
    self.assertEqual(10, otp.totp_count_valid_codes_handle(suffixstrip(self.handle)))
    self.assertFalse(otp.totp_is_active(suffixstrip(self.handle)))

    # go to 2nd setup page
    r = self.c.get('/en/2fa/set/2')
    self.assertEqual(200, r.status_code)

    re_secret = re.compile('id_otpsecret">([A-Z0-9]{16,16})<')
    m = re_secret.search(str(r.content))
    self.assertNotEqual(None, m)
    secret = m.groups()[0]

    # try 2 known-wrong codes
    for c in ['000', code_list[0]]:
      fields = {'otp': c}
      r = self.c.post('/en/2fa/set/2', fields)
      self.assertEqual(200, r.status_code)
      self.assertTrue('Wrong code, please try again' in str(r.content))
      self.assertFalse(otp.totp_is_active(suffixstrip(self.handle)))

    # send a correct code to activate
    fields = {'otp': pyotp.TOTP(secret).now()}
    r = self.c.post('/en/2fa/set/2', fields)
    self.assertEqual(b'', r.content)
    self.assertFalse('Wrong code, please try again' in str(r.content))
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/2fa/', r['Location'])

    r = self.c.get('/en/2fa/')
    self.assertEqual(200, r.status_code)
    self.assertTrue('Two-factor Authentication is set' in str(r.content))
    self.assertTrue('You currently have 10 recovery codes' in str(r.content))
    self.assertTrue(otp.totp_is_active(suffixstrip(self.handle)))

    # Generate new recovery codes

    # check a simple GET doesn't work
    r = self.c.get('/en/2fa/newrecovery')
    self.assertEqual(405, r.status_code)
    self.assertEqual(b'', r.content)

    r = self.c.post('/en/2fa/newrecovery')
    self.assertEqual(200, r.status_code)

    # extract all codes
    re_code = re.compile('<li>(\d{8,8})</li>')
    code_list = [m.groups()[0] for m in re_code.finditer(str(r.content))]
    self.assertEqual(10, len(code_list))


#
# Tests with a pre-configured account
#
class OtpTestSetAccount(TestCase):
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

    self.c = Client()

    # Do a Django login
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))

    r = self.c.get('/en/2fa/set/1')
    self.assertEqual(200, r.status_code)

    # get full list of codes
    re_codes = re.compile('((?:<li>\d{8,8}</li> ){10,10})')
    m = re_codes.search(str(r.content))
    self.assertNotEqual(None, m)

    # extract all codes
    re_code = re.compile('<li>(\d{8,8})</li>')
    self.code_list = [m.groups()[0] for m in re_code.finditer(str(r.content))]
    self.assertEqual(10, len(self.code_list))

    # go to 2nd setup page
    r = self.c.get('/en/2fa/set/2')
    self.assertEqual(200, r.status_code)

    re_secret = re.compile('id_otpsecret">([A-Z0-9]{16,16})<')
    m = re_secret.search(str(r.content))
    self.assertNotEqual(None, m)
    self.secret = m.groups()[0]

    # send a correct code to activate
    fields = {'otp': pyotp.TOTP(self.secret).now()}
    r = self.c.post('/en/2fa/set/2', fields)
    self.assertFalse('Wrong code, please try again' in str(r.content))

  def test_2fa_home(self):
    r = self.c.get('/en/2fa/')
    self.assertEqual(200, r.status_code)
    self.assertTrue('Two-factor Authentication is set' in str(r.content))
    self.assertTrue('You currently have 10 recovery codes' in str(r.content))
    self.assertTrue(otp.totp_is_active(suffixstrip(self.handle)))

  def test_2fa_newrecovery_get(self):
    # check a simple GET doesn't change anything
    r = self.c.get('/en/2fa/newrecovery')
    self.assertEqual(405, r.status_code)
    self.assertEqual(b'', r.content)
    self.assertTrue(otp.totp_is_active(suffixstrip(self.handle)))

  def test_2fa_newrecovery_post(self):
    r = self.c.post('/en/2fa/newrecovery')
    self.assertEqual(200, r.status_code)
    re_code = re.compile('<li>(\d{8,8})</li>')
    code_list = [m.groups()[0] for m in re_code.finditer(str(r.content))]
    self.assertEqual(10, len(code_list))
    self.assertTrue(otp.totp_is_active(suffixstrip(self.handle)))

  def test_2fa_deactivate_wrong1(self):
    # try a code from the recovery list
    fields = {'otp': '000'}
    r = self.c.post('/en/2fa/clear', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Wrong code, please try again' in str(r.content))
    self.assertTrue(otp.totp_is_active(suffixstrip(self.handle)))

  def test_2fa_deactivate_wrong2(self):
    # try a code from the recovery list
    fields = {'otp': self.code_list[0]}
    r = self.c.post('/en/2fa/clear', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Wrong code, please try again' in str(r.content))
    self.assertTrue(otp.totp_is_active(suffixstrip(self.handle)))

  def test_2fa_deactivate_good(self):
    fields = {'otp': pyotp.TOTP(self.secret).now()}
    r = self.c.post('/en/2fa/clear', fields)
    self.assertEqual(b'', r.content)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/2fa/', r['Location'])
    self.assertFalse(otp.totp_is_active(suffixstrip(self.handle)))

  def test_2fa_login_wrong(self):
    self.c.logout()
    # need to GET the login page once so that we get a cookie
    r = self.c.get('/en/login/')
    self.assertEqual(200, r.status_code)

    # enter the fixed password
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': self.pw})
    self.assertEqual(b'', r.content)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/2fa/login/', r['Location'])

    # Try a wrong OTP code
    fields = {'otp': '000'}
    r = self.c.post('/en/2fa/login/', fields)
    self.assertTrue('Sorry, your one-time password is incorrect' in str(r.content))
    self.assertEqual(200, r.status_code)

  def test_2fa_login_otp(self):
    self.c.logout()
    # need to GET the login page once so that we get a cookie
    r = self.c.get('/en/login/')
    self.assertEqual(200, r.status_code)

    # enter the fixed password
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': self.pw})
    self.assertEqual(b'', r.content)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/2fa/login/', r['Location'])

    # Try a correct OTP code
    fields = {'otp': pyotp.TOTP(self.secret).now()}
    r = self.c.post('/en/2fa/login/', fields)
    self.assertEqual(b'', r.content)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/', r['Location'])

  def test_2fa_login_recovery(self):
    self.c.logout()
    # need to GET the login page once so that we get a cookie
    r = self.c.get('/en/login/')
    self.assertEqual(200, r.status_code)

    # enter the fixed password
    r = self.c.post('/en/login/', {'handle': self.handle, 'password': self.pw})
    self.assertEqual(b'', r.content)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/2fa/login/', r['Location'])

    # Try a recovery code
    fields = {'otp': self.code_list[0]}
    r = self.c.post('/en/2fa/login/', fields)
    self.assertEqual(b'', r.content)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/', r['Location'])

    self.assertEqual(len(mail.outbox), 1)
    msg = str(mail.outbox[0].message())
    self.assertTrue('You now have 9 recovery codes left' in msg)
