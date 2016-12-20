import os
from typing import List

import dj_database_url
from vault12factor import VaultCredentialProvider, VaultAuth12Factor, DjangoAutoRefreshDBCredentialsDict

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INSTALLED_APPS = [
    'mailauth.MailAuthApp',
    'postgresql_setrole',
    'vault12factor',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
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
            ],
        },
    },
]

WSGI_APPLICATION = 'authserver.wsgi.application'

DEBUG = False  # overridden by factorise() if defined

import authserver.vendor.django12factor as django12factor
globals().update(django12factor.factorise())

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(asctime)s %(levelname)s %(message)s'
        },
    },
    'handlers': {
        'stdout': {
            'level': 'DEBUG',
            'formatter': 'simple',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
        }
    },
    'loggers': {
        '': {
            'handlers': ['stdout'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

if DEBUG:
    SECRET_KEY = "secretsekrit"  # FOR DEBUG ONLY!

if VaultAuth12Factor.has_envconfig() and os.getenv("VAULT_DATABASE_PATH"):
    VAULT = VaultAuth12Factor.fromenv()
    CREDS = VaultCredentialProvider("https://vault.local:8200/", VAULT,
                                    os.getenv("VAULT_DATABASE_PATH"),
                                    os.getenv("VAULT_CA", None), True,
                                    DEBUG)

    DATABASES = {
        "default": DjangoAutoRefreshDBCredentialsDict(CREDS, {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DATABASE_NAME", "authserver"),
            "USER": CREDS.username,
            "PASSWORD": CREDS.password,
            "HOST": "127.0.0.1",
            "PORT": "5432",
            "SET_ROLE": os.getenv("DATABASE_PARENTROLE", "authserver"),
        }),
    }


# dj_database_url sets the old psycopg2 database provider for Django, so we need to check for that too
if DATABASES["default"]["ENGINE"] == "django.db.backends.postgresql" or \
        DATABASES["default"]["ENGINE"] == "django.db.backends.postgresql_psycopg2":
    if os.getenv("POSTGRESQL_CA", None):
        # enable ssl
        DATABASES["default"]["HOST"] = "postgresql.local"
        DATABASES["default"]["OPTIONS"] = {
            "sslmode": "verify-full",
            "sslrootcert": os.getenv("POSTGRESQL_CA"),
        }
    if os.getenv("DB_SSLCERT", None):
        DATABASES["default"]["OPTIONS"] = {
            "sslcert": os.getenv("DB_SSLCERT"),
            "sslkey": os.getenv("DB_SSLKEY"),
        }

if DEBUG:
    ALLOWED_HOSTS = []  # type: List[str]
else:
    ALLOWED_HOSTS = ["auth.maurus.net", ]

AUTH_USER_MODEL = "mailauth.MNUser"

# Validate email addresses against our special DB structure
AUTHENTICATION_BACKENDS = ['mailauth.auth.MNUserAuthenticationBackend']

# we use our own modular crypt format sha256 hasher for maximum compatibility
# with Dovecot, OpenSMTPD etc.
PASSWORD_HASHERS = ['mailauth.auth.UnixCryptCompatibleSHA256Hasher']

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# third-party access credentials
SPAPI_DBUSERS = [s.strip() for s in os.getenv("SPAPI_DBUSERS", "").split(",")]

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATICFILES_DIRS = [os.path.join(BASE_DIR, "authserver", "static")]
