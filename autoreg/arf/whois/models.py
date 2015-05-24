# $Id$

import datetime

from django.db import models

from autoreg.whois.db import country_from_name


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
    country = models.CharField(max_length=2)
    phone = models.CharField(max_length=40)
    fax = models.CharField(max_length=40)
    passwd = models.CharField(max_length=34)
    created_on = models.DateTimeField()
    updated_by = models.CharField(max_length=64)
    validated_on = models.DateTimeField()
    updated_on = models.DateTimeField()
    private = models.BooleanField(default=False)
    class Meta:
        db_table = 'contacts'
        ordering = ['handle']
    def __str__(self):
        return self.name or ''
    def initial_form(self):
        """Return dictionary for initial fields of contact forms"""
        adlist = self.addr.rstrip().split('\n')
        initial = { 'pn1': self.name,
                    'em1': self.email,
                    'ph1': self.phone,
                    'fx1': self.fax,
                    'private': self.private }
        n = 1
        lastk = None
        for i in adlist:
          lastk = 'ad%d' % n
          initial[lastk] = i
          n += 1
        if self.country is not None:
          initial['ad6'] = self.country
        elif lastk and lastk != 'ad6':
          co = country_from_name(initial[lastk])
          if co:
            # For "legacy" contact records, if the last address line
            # looks like a country, convert it to an ISO country code
            # and move it to the 'ad6' field in the form.
            initial['ad6'] = co
            del initial[lastk]
        return initial

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
    private = models.BooleanField(default=False)
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

class Tokens(models.Model):
    id = models.AutoField(primary_key=True)
    contact_id = models.IntegerField()
    token = models.CharField(max_length=16, null=True)
    date = models.DateTimeField(default=datetime.datetime.today)
    expires = models.DateTimeField()
    action = models.CharField(max_length=10, null=True)
    args = models.CharField(max_length=200, null=True)
    class Meta:
        db_table = 'arf_tokens'


class Admins(models.Model):
    id = models.AutoField(primary_key=True)
    login = models.CharField(max_length=16, unique=True)
    contact = models.ForeignKey(Contacts)
    class Meta:
        db_table = 'admins'
        ordering = ['login']
    class Admin:
        pass
    def __str__(self):
        return self.login

def check_is_admin(handle):
  if not handle:
    return False
  return Admins.objects.filter(contact__handle=handle.upper()).exists()
