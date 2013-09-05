# $Id$

from django.db import models
from autoreg.arf.whois.models import Contacts

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
