# $Id$

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import io
import random
import time


import six


from django.conf import settings
from django.db import connection, models, transaction, IntegrityError
from django.utils.translation import ugettext_lazy, ugettext as _

from .. import util
from ..webdns.models import Zones, preempt
from ..whois.models import Contacts
import autoreg.common
import autoreg.conf
import autoreg.whois.db


class Requests(models.Model):
    id = models.CharField(max_length=30, primary_key=True)
    email = models.CharField(max_length=80)
    action = models.CharField(max_length=8)
    fqdn = models.CharField(max_length=200)
    zone = models.ForeignKey(Zones, on_delete=models.CASCADE)
    language = models.CharField(max_length=2)
    state = models.CharField(max_length=10)
    zonerecord = models.CharField(max_length=500)
    whoisrecord = models.CharField(max_length=2000)
    tags = models.CharField(max_length=50)
    contact = models.ForeignKey(Contacts, on_delete=models.CASCADE)
    pending_state = models.CharField(max_length=10, default=None, null=True)
    reason = models.CharField(max_length=80, default=None, null=True)
    reasonfield = models.CharField(max_length=1000, default=None, null=True)
    admin_contact = models.ForeignKey(Contacts, related_name='admin', on_delete=models.CASCADE, null=True)
    class Meta:
        db_table = 'requests'
        ordering = ['id']
    def __str__(self):
        return self.id
    class Admin:
        pass

    def _set_pending(self, pending, admin_contact, reason, reasonfield):
      self.pending_state = pending
      self.admin_contact = admin_contact
      if reason:
        self.reason = reason
      self.reasonfield = reasonfield
      self.save()
      return True

    def accept(self, admin_contact, reasonfield=None):
      return self._set_pending('Acc', admin_contact, None, reasonfield)

    def reject(self, admin_contact, reason, reasonfield):
      return self._set_pending('Rej', admin_contact, reason, reasonfield)

    def reject_preempt(self, admin_contact, reason, reasonfield):
      return self._set_pending('Pre', admin_contact, reason, reasonfield)

    def accept2(self, out, dd=None, whoisdb=None):
      r = self
      reasonfield = r.reasonfield
      email = r.admin_contact.email

      if settings.FORCEDEBUGMAIL:
        mailto = [settings.FORCEDEBUGMAIL]
      else:
        mailto = [r.email]

      # import here rather than at top of module to avoid weird name clashes
      # with the external "dns" module when running Django manage.py.
      import autoreg.dns.db

      outwhois = io.StringIO()

      err = None
      rrfile = io.StringIO(r.zonerecord)
      try:
        dd.new(r.fqdn, None, 'NS', file=rrfile)
      except autoreg.dns.db.AccessError as e:
        err = six.text_type(e)
      except autoreg.dns.db.DomainError as e:
        err = six.text_type(e)

      if err:
        print(_("Error:"), err, file=out)
        raise IntegrityError(_("Error:") + " " + err)

      print(_("Zone insert done\n"), file=out)

      inwhois = [line for line in r.whoisrecord.split('\n')
            if line != ''
            and not line.startswith('mnt-by:')
            and not line.startswith('source:')
            and not line.startswith('changed:')]
      inwhois.append('changed: ' + email)

      if not whoisdb.parsefile(inwhois, None, outfile=outwhois):
        print(outwhois.getvalue(), file=out)
        raise IntegrityError(_("Whois error, aborting"))

      print(outwhois.getvalue(), file=out)
      vars = {'rqid': self.id, 'domain': r.fqdn.upper(), 'to': r.email,
              'reasonfield': reasonfield,
              'from': autoreg.conf.FROMADDR,
              'sitename': autoreg.conf.SITENAME,
              'whoisrecord': outwhois.getvalue(), 'zonerecord': r.zonerecord}
      if not util.render_to_mail("whois/domainnew.mail", vars,
                                 autoreg.conf.FROMADDR, mailto,
                                 language=r.language):
        print(_("Mail to %(mails)s failed") % {'mails': ' '.join(mailto)},
              file=out)
        # we have to continue anyway, since the request has been executed

      r.state = 'Acc'
      r.save()
      r.delete()
      return True

    def reject2(self, out):
      r = self
      reason = r.reason
      reasonfield = r.reasonfield

      if settings.FORCEDEBUGMAIL:
        mailto = [settings.FORCEDEBUGMAIL]
      else:
        mailto = [r.email]

      action = ugettext_lazy("creation")

      vars = {'rqid': r.id, 'domain': r.fqdn.upper(), 'to': r.email,
              'action': action, 'reason': reason, 'reasonfield': reasonfield,
              'sitename': autoreg.conf.SITENAME,
              'from': autoreg.conf.FROMADDR}

      if not util.render_to_mail("whois/domainrej.mail", vars,
                                 autoreg.conf.FROMADDR, mailto,
                                 language=r.language):
        print(_("Mail to %(mails)s failed") % {'mails': ' '.join(mailto)},
              file=out)
        return False

      print(_("Mail to %(mails)s done") % {'mails': ' '.join(mailto)}, file=out)

      if r.pending_state == 'Pre':
        ok, err = preempt(r.admin_contact.handle, r.fqdn)
        if ok:
          print(_("Domain %s has been preempted") % r.fqdn, file=out)
        else:
          print(_("Domain %(fqdn)s has not been preempted: %(err)s") % {'fqdn': r.fqdn, 'err': err}, file=out)

      r.state = r.pending_state
      r.save()
      r.delete()
      return True

    def do_pending(self, out, dd, whoisdb):
      if self.pending_state == 'Acc':
        return self.accept2(out, dd, whoisdb)
      elif self.pending_state in ['Rej', 'Pre']:
        return self.reject2(out)
      return False

    def do_pending_exc(self, out, dd, whoisdb):
      ok = self.do_pending(out, dd, whoisdb)
      if not ok:
        # raise to force a transaction rollback by Django
        raise IntegrityError(_("Error executing %(rqid)s") % {'rqid': self.id})

    def remove(self, state):
      self.state = state
      self.save()
      self.delete()


class RequestsLog(models.Model):
    id = models.AutoField(primary_key=True)
    fqdn = models.CharField(max_length=255)
    contact = models.ForeignKey(Contacts, on_delete=models.CASCADE)
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
  dd = autoreg.dns.db.db(dbc=connection.cursor())
  dd.login('autoreg')
  whoisdb = autoreg.whois.db.Main(dbc=connection.cursor())

  rl = Requests.objects.exclude(pending_state=None).order_by('id')

  for r in rl:
    with transaction.atomic():
      r2 = Requests.objects.select_for_update().get(id=r.id)
      try:
        r2.do_pending_exc(out, dd, whoisdb)
        ok = True
      except IntegrityError as e:
        print(six.text_type(e), file=out)
        ok = False
      if ok:
        print(_("Status: committed"), file=out)
      else:
        print(_("Status: cancelled"), file=out)
