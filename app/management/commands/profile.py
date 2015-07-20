from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q

from app.errors import InvalidVersionError
from app.models import Revision
from app.helpers import get_version_components
from app.subjects import curl, ffmpeg
from app.utilities import profile


def check_revision(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        try:
            (ma, mi, bu) = get_version_components(value)

            if not Revision.objects.filter(number=value).exists():
                raise OptionValueError(
                    'Revision %s does not exist in the database.' % value
                )
        except InvalidVersionError:
            raise OptionValueError(
                'Invalid revision number specified. %s must be formatted as '
                '0.0.0' % opt_str
            )


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option(
            '-s', choices=settings.SUBJECTS, dest='subject'
        ),
        make_option(
            '-r', type='str', action='callback', callback=check_revision,
            dest='revision'
        ),
        make_option(
            '-i', type='int', action='store', dest='index'
        ),
    )
    help = (
        'Generates gprof.txt file for a corresponding gmon.out file.'
    )

    def handle(self, *args, **options):
        subject = options['subject']
        revision = options['revision']

        revisions = Revision.objects.filter(
            subject__name=subject, is_loaded=False
        )
        if 'ffmpeg' in subject:
            revisions = Revision.objects.filter(type='b')
            subject_cls = ffmpeg.FFmpeg
        elif 'curl' in subject:
            revisions = Revision.objects.filter(type='t')
            subject_cls = curl.cURL

        if revision:
            revisions = revisions.filter(number=revision)

        index = options.get('index', None)

        for revision in revisions:
            profile(revision, subject_cls, index)
