from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand

from app.errors import InvalidVersionError
from app.helpers import get_version_components
from app.models import Revision
from app.subjects import curl, ffmpeg, wireshark
from app.utilities import load


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
            '-s', choices=settings.SUBJECTS, dest='subject',
            help='Name of the subject to load the database with.'
        ),
        make_option(
            '-r', type='str', action='callback', callback=check_revision,
            dest='revision',
            help=(
                'Revision number of the subject to load the database with, '
                'e.g. 2.6.0. Default is None, in which case all revisions of'
                ' the subject are loaded.'
            )
        ),
    )
    help = (
        'Clone, checkout, build, test, and profile revisions of a '
        'subject. The profile information is used to measure the attack '
        'surface of the software. All metrics captured during the measurement'
        ' are then stored to the database by this command.'
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
        elif 'wireshark' in subject:
            revisions = Revision.objects.filter(type='b')
            subject_cls = wireshark.Wireshark

        if revision:
            revisions = revisions.filter(number=revision)

        num_processes = min(settings.PARALLEL['PROCESSES'], revisions.count())

        # TODO: Resolve daemonic process issue
        for revision in revisions:
            load(revision, subject_cls)
