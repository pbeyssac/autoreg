# $Id$

from __future__ import absolute_import


import io

import six

from django.db import connection, models

from django.utils.translation import ugettext as _

from autoreg.conf import PREEMPTHANDLE
import autoreg.dns.db
from ..whois.models import Admins, Contacts, ContactTypes, \
  DomainContact, Whoisdomains


class Zones(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(unique=True, max_length=255)
    minlen = models.IntegerField()
    maxlen = models.IntegerField()
    ttl = models.IntegerField()
    updateserial = models.BooleanField()
    soaserial = models.IntegerField()
    soarefresh = models.IntegerField()
    soaretry = models.IntegerField()
    soaexpires = models.IntegerField()
    soaminimum = models.IntegerField()
    soaprimary = models.CharField(max_length=255)
    soaemail = models.CharField(max_length=255)
    class Meta:
        db_table = 'zones'
        ordering = ['name']
    class Admin:
        list_display = ('name', 'soaserial', 'updateserial')
    def __str__(self):
        return self.name


class AdminZone(models.Model):
    id = models.AutoField(primary_key=True)
    zone_id = models.ForeignKey(Zones, on_delete=models.CASCADE, db_column='zone_id')
    admin_id = models.ForeignKey(Admins, on_delete=models.CASCADE, db_column='admin_id')
    class Meta:
        db_table = 'admin_zone'
        ordering = ['id']
    def __str__(self):
        return str(self.id)


class Domains(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=64)
    registry_hold = models.BooleanField()
    registry_lock = models.BooleanField()
    internal = models.BooleanField()
    zone = models.ForeignKey(Zones, on_delete=models.CASCADE)
    registrar_id = models.IntegerField()
    created_by = models.ForeignKey(Admins, on_delete=models.CASCADE, db_column='created_by', related_name='domains_created')
    created_on = models.DateTimeField()
    updated_by = models.ForeignKey(Admins, on_delete=models.CASCADE, db_column='updated_by')
    updated_on = models.DateTimeField()
    def fqdn(self):
        return self.name + '.' + self.zone.name
    class Meta:
        db_table = 'domains'
        ordering = ['name']
    class Admin:
        list_display = ('fqdn', 'updated_on', 'updated_by')
        list_filter = ['created_on', 'created_by', 'updated_on', 'updated_by']
        search_fields = ['name']
    def __str__(self):
        return self.name + '.' + self.zone.name

class Rrtypes(models.Model):
    id = models.IntegerField(primary_key=True)
    label = models.CharField(unique=True, max_length=10)
    class Meta:
        db_table = 'rrtypes'
        ordering = ['label']
    def __str__(self):
        return self.label

class Rrs(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(Domains, on_delete=models.CASCADE) # edit_inline=models.TABULAR
    ttl = models.IntegerField() # core=True
    rrtype = models.ForeignKey(Rrtypes, on_delete=models.CASCADE) # core=True
    created_on = models.DateTimeField() # core=True
    label = models.CharField(max_length=64) # core=True
    value = models.CharField(max_length=255) # core=True
    class Meta:
        db_table = 'rrs'
        ordering = ['label']
    def __str__(self):
        if self.ttl:
            ttl = str(self.ttl)
        else:
            ttl = ''
        return "%s %s%s %s" % (self.label, ttl, self.rrtype.label, self.value)

class AllowedRr(models.Model):
    id = models.AutoField(primary_key=True)
    zone = models.ForeignKey(Zones, on_delete=models.CASCADE) # edit_inline=models.TABULAR
    rrtype = models.ForeignKey(Rrtypes, on_delete=models.CASCADE) # core=True
    class Meta:
        db_table = 'allowed_rr'
    def __str__(self):
        return self.rrtype.label + " (" + self.zone.name + ")"

class DomainsHist(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=64)
    zone = models.ForeignKey(Zones, on_delete=models.CASCADE)
    registrar_id = models.IntegerField()
    created_by = models.ForeignKey(Admins, on_delete=models.CASCADE, db_column='created_by', related_name='domainshist_created')
    created_on = models.DateTimeField()
    deleted_by = models.ForeignKey(Admins, on_delete=models.CASCADE, db_column='deleted_by')
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'domains_hist'

class RrsHist(models.Model):
    id = models.IntegerField(primary_key=True)
    domain_id = models.IntegerField()
    ttl = models.IntegerField()
    rrtype = models.ForeignKey(Rrtypes, on_delete=models.CASCADE)
    created_on = models.DateTimeField()
    label = models.CharField(max_length=64)
    value = models.CharField(max_length=255)
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'rrs_hist'


def is_free(fqdn):
  """check domain availability"""
  fqdn = fqdn.upper()
  w = Whoisdomains.objects.filter(fqdn=fqdn).exists()
  if '.' in fqdn:
    name, zone = fqdn.split('.', 1)
  else:
    name, zone = fqdn, ''
  z = Domains.objects.filter(name=name, zone__name=zone).exists()
  return w, z

def is_orphan(fqdn):
  """check domain is an orphan
     1) should not exist in Whois
     2) should exist in zone
  """
  w, z = is_free(fqdn)
  if w:
    return False, _("exists in Whois")
  if not z:
    return False, _("does not exist in zone")
  return True, None

def is_preemptable(fqdn):
  """check domain is preemptable
     1) should not exist in Whois
     2) should not exist in zone
  """
  w, z = is_free(fqdn)
  if w:
    return False, _("exists in Whois")
  if z:
    return False, _("exists in zone")
  return True, None


def preempt(handle, fqdn):
  if not is_preemptable(fqdn):
    return False, _("Domain is not preemptable")

  fqdn = fqdn.upper()

  techtype = ContactTypes.objects.get(name='technical')
  registranttype = ContactTypes.objects.get(name='registrant')

  c1 = Contacts.objects.get(handle=handle)
  c2 = Contacts.objects.get(handle=PREEMPTHANDLE)

  wd = Whoisdomains(fqdn=fqdn)
  wd.save()
  rc = DomainContact(whoisdomain=wd, contact=c2, contact_type=registranttype)
  rc.save()
  tc = DomainContact(whoisdomain=wd, contact=c1, contact_type=techtype)
  tc.save()

  dd = autoreg.dns.db.db(dbc=connection.cursor())
  dd.login('autoreg')

  errors = None
  try:
    # create empty
    dd.new(fqdn, None, 'NS', file=io.StringIO())
  except autoreg.dns.db.DomainError as e:
    errors = six.text_type(e)
  except autoreg.dns.db.AccessError as e:
    errors = six.text_type(e)

  if errors:
    wd.delete()
    rc.delete()
    tc.delete()
    return False, errors

  return True, ""
