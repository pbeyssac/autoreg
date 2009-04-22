# $Id$

from django.db import models

class Whoisdomains(models.Model):
    id = models.AutoField(primary_key=True)
    fqdn = models.CharField(max_length=255, unique=True)
    created_on = models.DateTimeField()
    updated_by = models.CharField(max_length=64)
    updated_on = models.DateTimeField()
    class Meta:
        db_table = 'whoisdomains'
        ordering = ['fqdn']
    def __str__(self):
        return self.fqdn
    class Admin:
        pass

class ContactTypes(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=20)
    class Meta:
        db_table = 'contact_types'
        ordering = ['name']
    def __str__(self):
        return self.name

class Contacts(models.Model):
    id = models.AutoField(primary_key=True)
    handle = models.CharField(max_length=20, unique=True)
    exthandle = models.CharField(max_length=20)
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=80)
    addr = models.CharField(max_length=400)
    phone = models.CharField(max_length=40)
    fax = models.CharField(max_length=40)
    passwd = models.CharField(max_length=34)
    created_on = models.DateTimeField()
    updated_by = models.CharField(max_length=64)
    updated_on = models.DateTimeField()
    pw_reset_token = models.CharField(max_length=16)
    pw_reset_token_date = models.DateTimeField()
    class Meta:
        db_table = 'contacts'
        ordering = ['handle']
    def __str__(self):
        return self.name or ''
    class Admin:
        search_fields = ['handle']
        list_display = ('handle', 'name')

class DomainContact(models.Model):
    id = models.AutoField(primary_key=True)
    whoisdomain = models.ForeignKey(Whoisdomains)
    contact = models.ForeignKey(Contacts)
    contact_type = models.ForeignKey(ContactTypes)
    created_on = models.DateTimeField()
    class Meta:
        db_table = 'domain_contact'
    class Admin:
        pass
    def __str__(self):
        return "%s/%s/%s" % (self.contact.handle, self.contact_type.name, self.whoisdomain.fqdn)

class WhoisdomainsHist(models.Model):
    id = models.IntegerField(primary_key=True)
    whoisdomain_id = models.IntegerField()
    fqdn = models.CharField(max_length=255)
    created_on = models.DateTimeField()
    updated_by = models.CharField(max_length=64)
    updated_on = models.DateTimeField()
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'whoisdomains_hist'

class ContactsHist(models.Model):
    id = models.IntegerField(primary_key=True)
    contact_id = models.IntegerField()
    handle = models.CharField(max_length=20)
    exthandle = models.CharField(max_length=20)
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=80)
    addr = models.CharField(max_length=400)
    phone = models.CharField(max_length=40)
    fax = models.CharField(max_length=40)
    passwd = models.CharField(max_length=34)
    created_on = models.DateTimeField()
    updated_by = models.CharField(max_length=64)
    updated_on = models.DateTimeField()
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'contacts_hist'

class DomainContactHist(models.Model):
    id = models.AutoField(primary_key=True)
    whoisdomain_id = models.IntegerField()
    contact_id = models.IntegerField()
    contact_type = models.ForeignKey(ContactTypes)
    created_on = models.DateTimeField()
    deleted_on = models.DateTimeField()
    class Meta:
        db_table = 'domain_contact_hist'

