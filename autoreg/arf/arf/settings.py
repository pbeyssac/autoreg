# Django settings for arf project.
# -*- coding: utf-8 -*-
# $Id$

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Make this unique, and don't share it with anybody.
# This is used to generate hashes for session identifiers.
SECRET_KEY = open('/usr/local/autoreg/arf/SECRET_KEY').read()[:-1]

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ALLOWED_HOSTS = [
  'eu.org', 'www.eu.org'
]

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'autoreg.arf.dns',
    'autoreg.arf.requests',
    'autoreg.arf.whois'
)

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'autoreg.arf.arf.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [ "/usr/local/autoreg/arf/templates" ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'autoreg.arf.wsgi.application'

# Authentication backend using passwords from the whois contact database.
AUTHENTICATION_BACKENDS = ( 'autoreg.arf.whois.contactauth.AuthBackend', )

# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Europe/Paris'
USE_I18N = True
USE_L10N = True
USE_TZ = True

LANGUAGES = (
  ('en', 'English'),
  ('fr', 'Français'),
)

LOCALE_PATHS = (
	'/home/freenix/pb/autoreg/locale',
)

#
# Application-specific settings
#

from autoreg.conf import DATABASE_NAME

DATABASES = {
  'default': {
    'ENGINE': 'django.db.backends.postgresql_psycopg2',
    'NAME': DATABASE_NAME,
    'USER': 'www'
  }
}

ADMINS = (
    ('Pierre', 'pb@eu.org'),
    # ('Your Name', 'your_email@domain.com'),
)
MANAGERS = ADMINS
