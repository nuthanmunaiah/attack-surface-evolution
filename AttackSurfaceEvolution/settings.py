import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SECRET_KEY = 'm^$mg&@&rs-+6s2n0zr+4#jy!mh-6ekxjsf^t*n!4fw%v$9dq*'
DEBUG = True
TEMPLATE_DEBUG = True
ALLOWED_HOSTS = []
INSTALLED_APPS = (
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app',
)
MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)
ROOT_URLCONF = 'FFMpegEvolution.urls'
WSGI_APPLICATION = 'FFMpegEvolution.wsgi.application'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        'BULK': 50,
    }
}

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql_psycopg2',
#         'NAME': '',
#         'USER': '',
#         'PASSWORD': '',
#         'HOST': 'localhost',
#         'PORT': '5432',
#         'BULK': 999,
#     }
# }

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'America/New_York'
USE_I18N = True
USE_L10N = True
USE_TZ = True
TEMPLATE_DIRS = (
    os.path.join(BASE_DIR, 'templates'),
)

STATIC_URL = '/static/'

# FFmpeg CVEs Last Update SHA
FFMPEG_SECURITY_SRC_URL = (
    'https://api.github.com/repos/FFmpeg/web/contents/src/security'
)
FFMPEG_SECURITY_FILE_SHA = '67f2ec507f93f7cef5173081bd91c701cffc6bdc'

# Slack
SLACK_API_TOKEN_FILE = '.slackrc'
SLACK_CHANNEL = {'id': 'C03UY80BZ', 'name': '#nightly'}
SLACK_USERNAME = 'scrat'

# Parallel Execution
PARALLEL = {
    'PROCESSES': 1,
    'SUBPROCESSES': 25
}

# Subjects currently enabled
ENABLED_SUBJECTS = ['curl', 'ffmpeg', 'wireshark']
