from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import re

from django.test import TestCase

from ..webdns import models as webmodels
from ..whois import models as whoismodels
from . import models


class RqTest(TestCase):
  def setUp(self):
    pass
  def test_rq_make_id(self):
    r = re.compile('[0-9]{14}-arf-[0-9]+')
    self.assertEqual(True, r.match(models.rq_make_id()) != None)
  def test_rq(self):
    rqid = models.rq_make_id()
    zone = webmodels.Zones.objects.get(name='EU.ORG')

    c = whoismodels.Contacts(handle='PB1', name='Python Monthy', email='pm@local', addr='',
                             country='FR', private=True)
    c.save()

    req = models.Requests(id=rqid, action='N', language='EN',
                   email='foobar@local', fqdn='FOOBAR.EU.ORG', zone=zone,
                   state='Open',
                   contact=c,
                   zonerecord='\n',
                   whoisrecord='\n')
    req.save()

    rql = models.rq_list()
    self.assertEqual(1, len(rql))
    self.assertEqual(rqid, rql[0].id)

    rqid2 = models.rq_make_id()
    req2 = models.Requests(id=rqid2, action='N', language='EN',
                   email='foobar@local', fqdn='FOOBAR2.EU.ORG', zone=zone,
                   state='Open',
                   contact=c,
                   zonerecord='\n',
                   whoisrecord='\n')
    req2.save()

    rql = models.rq_list()
    self.assertEqual(2, len(rql))

    req2.delete()

    rql = models.rq_list()
    self.assertEqual(1, len(rql))
    self.assertEqual(rqid, rql[0].id)

    req.delete()
    rql = models.rq_list()
    self.assertEqual(0, len(rql))
