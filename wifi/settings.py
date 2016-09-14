# encoding: utf-8
"""
Django settings for wifi project.

For more information on this file, see
https://docs.djangoproject.com/en/1.7/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.7/ref/settings/
"""
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
import ConfigParser

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '1o5z^@fg5brb5+6#g&3ffet7vc#u4u4)9-u_@prn&1705dc&aw'

# SECURITY WARNING: don't run with debug turned on in production!

cfg = ConfigParser.SafeConfigParser()
cfg.read(os.path.join(BASE_DIR, 'espush.ini'))
DEBUG = cfg.getboolean('sys', 'debug')

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = [u'espush.cn',
                 u'www.espush.cn',]


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
)

WEB_APPS = ('weixin', 'webv2')
_INSTALLED_APPS = list(INSTALLED_APPS)
_INSTALLED_APPS.extend(WEB_APPS)
INSTALLED_APPS = tuple(_INSTALLED_APPS)


MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    # 'wifi.middleware.ProfilerMiddleware',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.template.context_processors.debug',
    'django.template.context_processors.i18n',
    'django.template.context_processors.media',
    'django.template.context_processors.static',
    'django.template.context_processors.tz',
    'django.template.context_processors.request',
    'django.contrib.messages.context_processors.messages',
)


ROOT_URLCONF = 'wifi.urls'

WSGI_APPLICATION = 'wifi.wsgi.application'

AUTH_USER_MODEL = 'webv2.User'
LOGIN_URL = "/webv2/login/"
# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases

'''
    'sqlite': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    },
'''

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'espush',
        'USER': 'espush',
        'PASSWORD': cfg.get('sys', 'db_password'),
        'HOST': cfg.get('sys', 'db_host'),
        'PORT': cfg.getint('sys', 'db_port')
    }
}
# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/

LANGUAGE_CODE = 'zh-CN'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = True

LANGUATES = (
    ('zh', 'Chinese'),
    ('en', 'English'),
)

LOCALE_PATH_LIST = [os.path.join(BASE_DIR, el, "locale") for el in WEB_APPS]
LOCAL_PATHS = tuple(LOCALE_PATH_LIST)

DATETIME_FORMAT = 'Y-m-d H:i'
DATE_FORMAT = 'Y-m-d'
TIME_FORMAT = 'H:i'

SESSION_COOKIE_AGE = 60 * 60 * 24 * 30
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.7/howto/static-files/


if 'LOCAL_TEST' in os.environ:
    SOCK_SERVER = '211.155.86.145:10082'
    LOCAL_TEST = True
else:
    SOCK_SERVER = 'localhost:10082'
    LOCAL_TEST = False


STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static').replace('\\', '/')


def path_join(path_el):
    return os.path.join(BASE_DIR, path_el, 'template').replace('\\', '/')


STATICFILES_DIRS = tuple([path_join(el) for el in WEB_APPS])

TEMPLATE_DIRS = tuple([path_join(el) for el in WEB_APPS])

UPLOAD_DIR = os.path.join(BASE_DIR, 'upload/rom')

# static files hash cache.

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.CachedStaticFilesStorage'

# #日志处理
logpath = os.path.join(BASE_DIR, 'log', 'espush.log')
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
       'standard': {
            'format': '[%(asctime)s %(module)s:%(funcName)s:%(lineno)d '\
            '%(levelname)s - %(message)s'},
       'djangofmt': {
            'format': '[%(asctime)s %(module)s:%(funcName)s:%(lineno)d '\
            '%(levelname)s - %(message)s'
            },
    },
    'filters': {
    },
    'handlers': {
        'espush': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': logpath,
            'maxBytes': 1024 * 1024 * 5,
            'backupCount': 5,
            'formatter': 'standard',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'djangofmt'
        },
    },
    'loggers': {
        'espush': {
            'handlers': ['espush', 'console', ],
            'level': 'DEBUG',
            'propagate': True
        },
        'django': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'ERROR',
        },
    },
}

IDENTIFY_IMAGE_FONTS = 'onestroke.ttf'

CRONTAB_RPC_URL = u'http://localhost:9998/'
REDIS_HOST = u'localhost'
DOCS_WEBSITE = u'http://docs.espush.cn/'

ROMS_UPLOAD_DIR = os.path.join(BASE_DIR, 'roms')
