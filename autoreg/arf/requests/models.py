# $Id$

from __future__ import print_function

import io
import random
import time

import psycopg2

from django.db import models

import autoreg.arf.util
from autoreg.arf.whois.models import Contacts
import autoreg.conf
import autoreg.dns.db
import autoreg.whois.db

class Requests(models.Model):
    id = models.CharField(max_length=30, primary_key=True)
    email = models.CharField(max_length=80)
    action = models.CharField(max_length=8)
    fqdn = models.CharField(max_length=200)
    language = models.CharField(max_length=2)
    state = models.CharField(max_length=10)
    zonerecord = models.CharField(max_length=500)
    whoisrecord = models.CharField(max_length=2000)
    tags = models.CharField(max_length=50)
    private = models.BooleanField(default=False)
    class Meta:
        db_table = 'requests'
        ordering = ['id']
    def __str__(self):
        return self.id
    class Admin:
        pass

class Admins(models.Model):
    id = models.AutoField(primary_key=True)
    login = models.CharField(unique=True, max_length=16)
    contact = models.ForeignKey(Contacts)
    class Meta:
        db_table = 'admins'
    def __str__(self):
        return self.login
    class Admin:
        pass


def rq_make_id(origin='arf'):
  return ''.join([time.strftime('%Y%m%d%H%M%S'), '-', origin, '-',
                 str(random.getrandbits(16))])

def rq_accept(out, rqid, login, email):
  rl = Requests.objects.filter(id=rqid)
  if rl.count() == 0:
    print(u"Request %s not found" % rqid, file=out)
    return False
  r = rl[0]

  mailto = [r.email]

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login(login)

  w = autoreg.whois.db.Main(dbh)
  outwhois = io.StringIO()

  if r.action == 'N':
    rrfile = io.StringIO(r.zonerecord)
    dd.new(r.fqdn, None, 'NS', file=rrfile, commit=False)
    print(u"Zone insert done\n", file=out)

    inwhois = [line for line in r.whoisrecord.split('\n')
          if line != ''
          and not line.startswith('mnt-by:')
          and not line.startswith('source:')
          and not line.startswith('changed:')]
    inwhois.append(u'changed: ' + email)

    if not w.parsefile(inwhois, None, commit=True, outfile=outwhois):
      print(outwhois.getvalue(), file=out)
      return False

    print(outwhois.getvalue(), file=out)
    vars = {'rqid': rqid, 'domain': r.fqdn.upper(), 'to': r.email,
            'whoisrecord': outwhois.getvalue(), 'zonerecord': r.zonerecord}
    if not autoreg.arf.util.render_to_mail("whois/domainnew.mail", vars,
                                           autoreg.conf.FROMADDR, mailto):
      print(u"Mail to %s failed" % ' '.join(mailto), file=out)
      # we have to continue anyway, since the request has been executed

  elif r.action == 'D':
    dd.delete(r.fqdn, None, commit=False)
    print(u"Zone delete done\n", file=out)

    inwhois = ['domain: '+r.fqdn.upper(), 'delete: '+login]

    if not w.parsefile(inwhois, None, commit=True, outfile=outwhois):
      print(outwhois.getvalue(), file=out)
      return False

    print(outwhois.getvalue(), file=out)
    vars = {'rqid': rqid, 'domain': r.fqdn.upper(), 'to': r.email}
    if not autoreg.arf.util.render_to_mail("whois/domaindel.mail", vars,
                                           autoreg.conf.FROMADDR, mailto):
      print(u"Mail to %s failed" % ' '.join(mailto), file=out)
      # we have to continue anyway, since the request has been executed

  r.state = 'Acc'
  r.save()
  r.delete()
  return True
