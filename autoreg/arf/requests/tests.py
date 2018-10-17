from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import io
import re
import sys


from django.db import connection
from django.test import TestCase, Client

from autoreg.util import pwcrypt
from autoreg.whois.db import Person, suffixadd, suffixstrip
from ..webdns import models as webmodels
from ..whois import models as whoismodels
from .models import Requests, rq_make_id, rq_list
from .management.commands import rqrun

class RqTest(TestCase):
  def setUp(self):
    pass
  def test_rq_make_id(self):
    r = re.compile('[0-9]{14}-arf-[0-9]+')
    self.assertEqual(True, r.match(rq_make_id()) != None)
  def test_rq(self):
    rqid = rq_make_id()
    zone = webmodels.Zones.objects.get(name='EU.ORG')

    c = whoismodels.Contacts(handle='PB1', name='Python Monthy', email='pm@local', addr='',
                             country='FR', private=True)
    c.save()

    req = Requests(id=rqid, action='N', language='EN',
                   email='foobar@local', fqdn='FOOBAR.EU.ORG', zone=zone,
                   state='Open',
                   contact=c,
                   zonerecord='\n',
                   whoisrecord='\n')
    req.save()

    rql = rq_list()
    self.assertEqual(1, len(rql))
    self.assertEqual(rqid, rql[0].id)

    rqid2 = rq_make_id()
    req2 = Requests(id=rqid2, action='N', language='EN',
                   email='foobar@local', fqdn='FOOBAR2.EU.ORG', zone=zone,
                   state='Open',
                   contact=c,
                   zonerecord='\n',
                   whoisrecord='\n')
    req2.save()

    rql = rq_list()
    self.assertEqual(2, len(rql))

    req2.delete()

    rql = rq_list()
    self.assertEqual(1, len(rql))
    self.assertEqual(rqid, rql[0].id)

    req.delete()
    rql = rq_list()
    self.assertEqual(0, len(rql))


class RqViewsTest(TestCase):
  def setUp(self):
    self.zone = webmodels.Zones.objects.get(name='EU.ORG')

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
    a = whoismodels.Admins(login='AA1', contact=whoismodels.Contacts.objects.get(handle='AA1'))
    a.save()
    self.admin = a
    self.admin_handle = p3.gethandle()

    rqid = rq_make_id()
    req = Requests(id=rqid, action='N', language='EN',
                   email='foobar@local', fqdn='FOOBAR.EU.ORG', zone=self.zone,
                   state='Open',
                   contact=whoismodels.Contacts.objects.get(handle=suffixstrip(self.handle)),
                   admin_contact=whoismodels.Contacts.objects.get(handle=suffixstrip(self.admin_handle)),
                   zonerecord='\n',
                   whoisrecord="domain: %s\naddress: Address éœ line 1\n"
                               "tech-c: %s\nadmin-c: %s\nprivate: yes\n"
                                % ('FOOBAR.EU.ORG', self.handle, self.handle))
    req.save()
    self.req = req

    self.c = Client()

  def test_rq_get_ko_1(self):
    r = self.c.get('/en/rq/' + self.req.id)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/rq/'+self.req.id, r['Location'])
  def test_rq_get_ko_2(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/rq/' + self.req.id)
    self.assertEqual(403, r.status_code)
  def test_rq_get_ok(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/rq/' + self.req.id)
    self.assertEqual(403, r.status_code)
  def test_rq_get_ok(self):
    webmodels.AdminZone(zone_id=self.zone, admin_id=self.admin).save()
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/rq/' + self.req.id)
    self.assertEqual(200, r.status_code)

  def test_rqedit_get_ko_1(self):
    r = self.c.get('/en/rqe/' + self.req.id)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/rqe/'+self.req.id, r['Location'])
  def test_rqedit_post_ko_1(self):
    r = self.c.post('/en/rqe/' + self.req.id)
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/login/?next=/en/rqe/'+self.req.id, r['Location'])
  def test_rqedit_get_ko_2(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.get('/en/rqe/' + self.req.id)
    self.assertEqual(403, r.status_code)
  def test_rqedit_post_ko_2(self):
    self.assertTrue(self.c.login(username=self.handle, password=self.pw))
    r = self.c.post('/en/rqe/' + self.req.id)
    self.assertEqual(403, r.status_code)

  def test_rqedit_get_ok(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/rqe/' + self.req.id)
    self.assertEqual(403, r.status_code)
  def test_rqedit_post_ok_1(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.post('/en/rqe/' + self.req.id)
    self.assertEqual(403, r.status_code)
  def test_rqedit_post_ko_3(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    fields = {'tags': 'toto'}
    r = self.c.post('/en/rqe/' + self.req.id, fields)
    self.assertEqual(403, r.status_code)

  def test_rqlistdom_get_ko_1(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/rd')
    self.assertEqual(400, r.status_code)
  def test_rqlistdom_get_ok_1(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/rd/FOOBAR.EU.ORG')
    self.assertEqual(200, r.status_code)

  def test_rqlist_get_ok_1(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/r')
    self.assertEqual(301, r.status_code)
  def test_rqlist_get_ok_2(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/r/')
    self.assertEqual(302, r.status_code)
    self.assertEqual('/en/r/1', r['Location'])
  def test_rqlist_get_ok_3(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/r/1')
    self.assertEqual(200, r.status_code)

  def test_rqloglist_get_ok(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    r = self.c.get('/en/rl')
    self.assertEqual(200, r.status_code)

  def test_rqrun_1(self):
    c = rqrun.Command()
    outfile = io.StringIO()
    c.handle(outfile=sys.stdout)
    self.assertEqual('', outfile.getvalue())

  def test_rqval_1(self):
    r = self.c.post('/en/val', {})
    self.assertEqual(302, r.status_code)

  def test_rqval_2(self):
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    fields = {
      'rq1': self.req.id,
      'action1': 'accept',
      'reason1': ''
    }
    r = self.c.post('/en/val', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Permission denied on' in str(r.content))

  def test_rqrun_2(self):
    webmodels.AdminZone(zone_id=self.zone, admin_id=self.admin).save()
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    fields = {
      'rq1': self.req.id,
      'action1': 'accept',
      'reason1': ''
    }
    r = self.c.post('/en/val', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Accepted '+self.req.id+' (queued)' in str(r.content))
    c = rqrun.Command()
    outfile = io.BytesIO()
    c.handle(outfile=outfile)
    self.assertTrue(b'Zone insert done' in outfile.getvalue())

  def test_rqrun_3(self):
    webmodels.AdminZone(zone_id=self.zone, admin_id=self.admin).save()
    self.assertTrue(self.c.login(username=self.admin_handle, password=self.pw3))
    fields = {
      'rq1': self.req.id,
      'action1': 'delete',
      'reason1': ''
    }
    r = self.c.post('/en/val', fields)
    self.assertEqual(200, r.status_code)
    self.assertTrue('Deleted '+self.req.id in str(r.content))
    c = rqrun.Command()
    outfile = io.StringIO()
    c.handle(outfile=outfile)
    self.assertEqual('', outfile.getvalue())
