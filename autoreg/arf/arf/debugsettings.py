# Django settings for arf project.
# -*- coding: utf-8 -*-
# $Id$

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Make this unique, and don't share it with anybody.
# This is used to generate hashes for session identifiers.
SECRET_KEY = open('/usr/local/autoreg/arf/SECRET_KEY').read()[:-1]

DEBUG = True
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
    'django.contrib.sites',
    'autoreg.arf.webdns',
    'autoreg.arf.logs',
    'autoreg.arf.man',
    'autoreg.arf.requests',
    'autoreg.arf.whois'
)


TIME_ZONE = 'Europe/Paris'
LANGUAGE_CODE = 'en-us'
USE_I18N = True
USE_L10N = True

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'


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
        'DIRS': [
            "/usr/local/autoreg/arf/templates-devel",
            "/home/freenix/pb/autoreg/templates"
          ],
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

SESSION_COOKIE_NAME = 'dsession_id'

ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS
FORCEDEBUGMAIL='pb@eu.org'

RECAPTCHA_PUBLIC_KEY='6LdLMRkTAAAAACM-hHnNRNq_ptBpeU6W_5AL8-ta'
RECAPTCHA_PRIVATE_KEY='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
RECAPTCHA_API_URL='https://www.google.com/recaptcha/api/siteverify'
RECAPTCHA_REQUESTS_MIN=10
RECAPTCHA_DOMAINS_MIN=10
