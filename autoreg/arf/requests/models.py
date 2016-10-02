# $Id$

from __future__ import absolute_import
from __future__ import print_function

import io
import random
import time

import psycopg2

from django.conf import settings
from django.db import models, transaction, IntegrityError
from django.utils.translation import ugettext_lazy, ugettext as _

from .. import util
from ..whois.models import Contacts
import autoreg.common
import autoreg.conf
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
    contact = models.ForeignKey(Contacts)
    pending_state = models.CharField(max_length=10, default=None)
    reason = models.CharField(max_length=80, default=None)
    reasonfield = models.CharField(max_length=1000, default=None)
    admin_login = models.CharField(max_length=16, default=None)
    admin_email = models.CharField(max_length=80, default=None)
    class Meta:
        db_table = 'requests'
        ordering = ['id']
    def __str__(self):
        return self.id
    class Admin:
        pass

    def accept(self, login, email, reasonfield=None):
      self.pending_state = 'Acc'
      self.reasonfield = reasonfield
      self.admin_login = login
      self.admin_email = email
      self.save()
      return True

    def accept2(self, out, dd=None, whoisdb=None):
      r = self
      reasonfield = r.reasonfield
      login = r.admin_login
      email = r.admin_email

      if settings.FORCEDEBUGMAIL:
        mailto = [settings.FORCEDEBUGMAIL]
      else:
        mailto = [r.email]

      # import here rather than at top of module to avoid weird name clashes
      # with the external "dns" module when running Django manage.py.
      import autoreg.dns.db

      outwhois = io.StringIO()

      if r.action == 'N':
        err = None
        rrfile = io.StringIO(r.zonerecord)
        try:
          dd.new(r.fqdn, None, 'NS', file=rrfile, commit=False)
        except autoreg.dns.db.AccessError as e:
          err = unicode(e)
        except autoreg.dns.db.DomainError as e:
          err = unicode(e)

        if err:
          print(_("Error:"), err, file=out)
          return False

        print(_("Zone insert done\n"), file=out)

        inwhois = [line for line in r.whoisrecord.split('\n')
              if line != ''
              and not line.startswith('mnt-by:')
              and not line.startswith('source:')
              and not line.startswith('changed:')]
        inwhois.append(u'changed: ' + email)

        if not whoisdb.parsefile(inwhois, None, commit=True, outfile=outwhois):
          print(outwhois.getvalue(), file=out)
          return False

        print(outwhois.getvalue(), file=out)
        vars = {'rqid': self.id, 'domain': r.fqdn.upper(), 'to': r.email,
                'reasonfield': reasonfield,
                'from': autoreg.conf.FROMADDR,
                'whoisrecord': outwhois.getvalue(), 'zonerecord': r.zonerecord}
        if not util.render_to_mail("whois/domainnew.mail", vars,
                                   autoreg.conf.FROMADDR, mailto,
                                   language=r.language):
          print(_("Mail to %(mails)s failed") % {'mails': ' '.join(mailto)},
                file=out)
          # we have to continue anyway, since the request has been executed

      elif r.action == 'D':
        err, ok = None, False
        try:
          ok = autoreg.common.domain_delete(dd, r.fqdn, w, out, None)
        except autoreg.dns.db.AccessError as e:
          err = unicode(e)
        except autoreg.dns.db.DomainError as e:
          err = unicode(e)
        if not ok:
          if err:
            print(unicode(err), file=out)
          return False

        vars = {'rqid': self.id, 'domain': r.fqdn.upper(), 'to': r.email,
                'from': autoreg.conf.FROMADDR}
        if not util.render_to_mail("whois/domaindel.mail", vars,
                                   autoreg.conf.FROMADDR, mailto,
                                   language=r.language):
          print(_("Mail to %(mails)s failed") % {'mails': ' '.join(mailto)},
                file=out)
          # we have to continue anyway, since the request has been executed

      r.state = 'Acc'
      r.save()
      r.delete()
      return True

    def reject(self, login, reason, reasonfield):
      self.pending_state = 'Rej'
      self.admin_login = login
      self.reason = reason
      self.reasonfield = reasonfield
      self.save()
      return True

    def reject2(self, out):
      r = self
      reason = r.reason
      reasonfield = r.reasonfield

      if settings.FORCEDEBUGMAIL:
        mailto = [settings.FORCEDEBUGMAIL]
      else:
        mailto = [r.email]

      if r.action == 'N':
        action = ugettext_lazy("creation")
      elif r.action == 'D':
        action = ugettext_lazy("deletion")
      else:
        action = "???"

      vars = {'rqid': r.id, 'domain': r.fqdn.upper(), 'to': r.email,
              'action': action, 'reason': reason, 'reasonfield': reasonfield,
              'from': autoreg.conf.FROMADDR}

      if not util.render_to_mail("whois/domainrej.mail", vars,
                                 autoreg.conf.FROMADDR, mailto,
                                 language=r.language):
        print(_("Mail to %(mails)s failed") % {'mails': ' '.join(mailto)},
              file=out)
        return False

      print(_("Mail to %(mails)s done") % {'mails': ' '.join(mailto)}, file=out)

      r.state = 'Rej'
      r.save()
      r.delete()
      return True

    def do_pending(self, out, dd, whoisdb):
      if self.pending_state == 'Acc':
        return self.accept2(out, dd, whoisdb)
      elif self.pending_state == 'Rej':
        return self.reject2(out)
      return False

    def do_pending_exc(self, out, dd, whoisdb):
      ok = self.do_pending(out, dd, whoisdb)
      if not ok:
        # raise to force a transaction rollback by Django
        raise IntegrityError(_("Error executing %(rqid)s" % {'rqid': self.id}))

    def remove(self, state):
      self.state = state
      self.save()
      self.delete()


class RequestsLog(models.Model):
    id = models.AutoField(primary_key=True)
    fqdn = models.CharField(max_length=255)
    contact = models.ForeignKey(Contacts)
    date = models.DateTimeField()
    output = models.CharField(max_length=20000)
    errors = models.IntegerField()
    warnings = models.IntegerField()
    class Meta:
        db_table = 'requests_log'


def rq_make_id(origin='arf'):
  return ''.join([time.strftime('%Y%m%d%H%M%S'), '-', origin, '-',
                 str(random.getrandbits(16))])

def rq_list_unordered():
  return Requests.objects.filter(state='Open', pending_state=None)

def rq_list():
  return rq_list_unordered().order_by('id')

def rq_run(out):
  import autoreg.dns.db
  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login('autoreg')
  whoisdb = autoreg.whois.db.Main(dbh)

  rl = Requests.objects.exclude(pending_state=None).order_by('id')

  for r in rl:
    with transaction.atomic():
      r2 = Requests.objects.select_for_update().get(id=r.id)
      try:
        r2.do_pending_exc(out, dd, whoisdb)
        ok = True
      except IntegrityError as e:
        print(unicode(e), file=out)
        ok = False
      if ok:
        dbh.commit()
        print(_("Status: committed"), file=out)
      else:
        dbh.rollback()
        print(_("Status: cancelled"), file=out)
