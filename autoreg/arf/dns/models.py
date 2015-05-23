# $Id$

from django.db import models

from autoreg.arf.whois.models import Admins


class Zones(models.Model):
    id = models.IntegerField(primary_key=True)
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

class Domains(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=64)
    registry_hold = models.BooleanField()
    registry_lock = models.BooleanField()
    internal = models.BooleanField()
    zone = models.ForeignKey(Zones)
    registrar_id = models.IntegerField()
    created_by = models.ForeignKey(Admins, db_column='created_by', related_name='domains_created')
    created_on = models.DateTimeField()
    updated_by = models.ForeignKey(Admins, db_column='updated_by')
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
    id = models.IntegerField(primary_key=True)
    domain = models.ForeignKey(Domains) # edit_inline=models.TABULAR
    ttl = models.IntegerField() # core=True
    rrtype = models.ForeignKey(Rrtypes) # core=True
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
    id = models.IntegerField(primary_key=True)
    zone = models.ForeignKey(Zones) # edit_inline=models.TABULAR
    rrtype = models.ForeignKey(Rrtypes) # core=True
    class Meta:
        db_table = 'allowed_rr'
    def __str__(self):
        return self.rrtype.label + " (" + self.zone.name + ")"

class DomainsHist(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=64)
    zone = models.ForeignKey(Zones)
    registrar_id = models.IntegerField()
    created_by = models.ForeignKey(Admins, db_column='created_by', related_name='domainshist_created')
    created_on = models.DateTimeField()
    deleted_by = models.ForeignKey(Admins, db_column='deleted_by')
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'domains_hist'

class RrsHist(models.Model):
    id = models.IntegerField(primary_key=True)
    domain_id = models.IntegerField()
    ttl = models.IntegerField()
    rrtype = models.ForeignKey(Rrtypes)
    created_on = models.DateTimeField()
    label = models.CharField(max_length=64)
    value = models.CharField(max_length=255)
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'rrs_hist'

