# $Id$

from __future__ import absolute_import


from django.db import models
from django.utils import timezone


from ..whois.models import Contacts


class Log(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateTimeField(default=timezone.now)
    contact = models.ForeignKey(Contacts, on_delete=models.CASCADE)
    action = models.CharField(max_length=10)
    message = models.CharField(max_length=300, null=True)
    class Meta:
        db_table = 'log'
        ordering = ['date']


def log(handle, action, message=None):
  l = Log(contact=Contacts.objects.get(handle=handle), action=action,
          message=message)
  l.save()
