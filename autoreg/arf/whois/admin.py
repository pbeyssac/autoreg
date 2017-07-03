from django.contrib import admin
from .models import Contacts, DomainContact, Whoisdomains

admin.site.register(Contacts)
admin.site.register(DomainContact)
admin.site.register(Whoisdomains)
