import os
from typing import List

import dj_database_url
from vault12factor import VaultCredentialProvider, VaultAuth12Factor, DjangoAutoRefreshDBCredentialsDict

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INSTALLED_APPS = [
    'mailauth.MailAuthApp',
    'dockerauth.DockerAuthApp',
    'postgresql_setrole',
    'django_dbconn_retry',
    'vault12factor',
    'oauth2_provider',
    'mama_cas',
    'corsheaders',
    'django_select2',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'authserver.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, "authserver", "templates")],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'authserver.context_processors.branding'
            ],
        },
    },
]

WSGI_APPLICATION = 'authserver.wsgi.application'

LOGIN_URL = "authserver-login"
LOGIN_REDIRECT_URL = "/"
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

DEBUG = False  # overridden by factorise() if defined

import authserver.vendor.django12factor as django12factor
globals().update(django12factor.factorise())

# order is important here, because we'll overwrite LOGGING with factorise() otherwise
from authserver.gunicorn_conf import LOGGING

if DEBUG:
    SECRET_KEY = "secretsekrit"  # FOR DEBUG ONLY!

VAULT_ADDRESS = os.getenv("VAULT_ADDR", "https://vault.local:8200/")
VAULT_CA = os.getenv("VAULT_CA", None)

if VaultAuth12Factor.has_envconfig() and os.getenv("VAULT_DATABASE_PATH"):
    VAULT = VaultAuth12Factor.fromenv()
    CREDS = VaultCredentialProvider(VAULT_ADDRESS, VAULT,
                                    os.getenv("VAULT_DATABASE_PATH"),
                                    VAULT_CA, True,
                                    DEBUG)

    DATABASES = {
        "default": DjangoAutoRefreshDBCredentialsDict(CREDS, {
            "ENGINE": 'django.db.backends.postgresql',
            "NAME": os.getenv("DATABASE_NAME", "authserver"),
            "USER": CREDS.username,
            "PASSWORD": CREDS.password,
            "HOST": "127.0.0.1",
            "PORT": "5432",
            "SET_ROLE": os.getenv("DATABASE_PARENTROLE", "authserver"),
        }),
    }


# dj_database_url sets the old psycopg2 database provider for Django, so we need to check for that too
if DATABASES["default"]["ENGINE"] == 'django.db.backends.postgresql' or \
        DATABASES["default"]["ENGINE"] == 'django.db.backends.postgresql_psycopg2':
    if "OPTIONS" not in DATABASES["default"]:
        DATABASES["default"]["OPTIONS"] = {}

    if os.getenv("POSTGRESQL_CA", None):
        # enable ssl
        DATABASES["default"]["HOST"] = "postgresql.local"
        DATABASES["default"]["OPTIONS"]["sslmode"] = "verify-full"
        DATABASES["default"]["OPTIONS"]["sslrootcert"] = os.getenv("POSTGRESQL_CA")

    if os.getenv("DB_SSLCERT", None) and not (VaultAuth12Factor.has_envconfig() and
                                                  os.getenv("VAULT_DATABASE_PATH", None)):
        DATABASES["default"]["OPTIONS"]["sslcert"] = os.getenv("DB_SSLCERT")
        DATABASES["default"]["OPTIONS"]["sslkey"] = os.getenv("DB_SSLKEY")

if DEBUG:
    ALLOWED_HOSTS = ['*',]  # type: List[str]
    CORS_ORIGIN_ALLOW_ALL = True
else:
    CORS_ORIGIN_WHITELIST = os.getenv("CORS_ORIGIN_WHITELIST", "").split(',')
    CORS_ORIGIN_REGEX_WHITELIST = os.getenv("CORS_ORIGIN_REGEX_WHITELIST", "").split(',')

DOCKERAUTH_ALLOW_UNCONFIGURED_REPOS = django12factor.getenv_bool("DOCKERAUTH_ALLOW_UNCONFIGURED_REPOS")

JWT_CERTIFICATE_DAYS_VALID = int(os.getenv("JWT_CERT_DAYS_VALID", "365"))

AUTH_USER_MODEL = 'mailauth.MNUser'

# Validate email addresses against our special DB structure
AUTHENTICATION_BACKENDS = [
    'mailauth.auth.MNUserAuthenticationBackend',
]

# the one exception to the OAUTH2_PROVIDER dict, because this uses Django's 'swappable' builtin
OAUTH2_PROVIDER_APPLICATION_MODEL = 'mailauth.MNApplication'

OAUTH2_PROVIDER = {
    #'SCOPES_BACKEND_CLASS': 'mailauth.scopes.MNAuthScopes',
    'OAUTH2_VALIDATOR_CLASS': 'mailauth.oauth2.ClientPermissionValidator',
}

# we use our own modular crypt format sha256 hasher for maximum compatibility
# with Dovecot, OpenSMTPD etc.
PASSWORD_HASHERS = ['mailauth.auth.UnixCryptCompatibleSHA256Hasher']

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        "NAME": 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        "NAME": 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        "NAME": 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

USE_X_FORWARDED_HOST = django12factor.getenv_bool("USE_X_FORWARDED_HOST")

# third-party access credentials
SPAPI_DBUSERS = [s.strip() for s in os.getenv("SPAPI_DBUSERS", "").split(",")]

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATICFILES_DIRS = [os.path.join(BASE_DIR, "authserver", "static")]

# Authentication providers
MAMA_CAS_SERVICES = []  # type: List[str]  # currently none

# APP CONFIG
COMPANY_NAME = "maurus.networks"
COMPANY_LOGO_URL = "/static/mn.png"

SELECT2_JS = '/static/vendor/select2/select2.full.min.js'
SELECT2_CSS = '/static/vendor/select2/select2.min.css'
SELECT2_I18N = '/static/vendor/select2/i18n'
