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
  'eu.org', 'www.eu.org', 'nic.eu.org'
]

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'django.contrib.messages',
    'django.contrib.sites',
    'autoreg',
    'autoreg.arf',		# for templates & static web files
    'autoreg.arf.webdns',
    'autoreg.arf.logs',
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
        'DIRS': [ ],
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
	'/usr/local/autoreg/arf/locale',
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
FORCEDEBUGMAIL=''

RECAPTCHA_PUBLIC_KEY='6LdLMRkTAAAAACM-hHnNRNq_ptBpeU6W_5AL8-ta'
RECAPTCHA_PRIVATE_KEY='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
RECAPTCHA_API_URL='https://www.google.com/recaptcha/api/siteverify'
RECAPTCHA_REQUESTS_MIN=10
RECAPTCHA_DOMAINS_MIN=10

LANGUAGE_COOKIE_AGE=1209600
CSRF_COOKIE_HTTPONLY=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_AGE=1209600
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SECURE=True
SITE_ID=1
STATIC_URL='/arf/en/admin/static/'
