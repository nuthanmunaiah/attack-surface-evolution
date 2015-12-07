from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q

from app import constants, helpers, utilities, subjects
from app.errors import InvalidVersionError
from app.models import *
from app.subjects import curl, ffmpeg


def check_revision(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        try:
            ma, mi, pa = helpers.get_version_components(value)
            releases = Release.objects.filter(major=ma, minor=mi, patch=pa)

            if not releases.exists():
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
            '-s', choices=list(constants.SUBJECTS.keys()), dest='subject'
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
        release = options['revision']
        index = options['index']

        if subject not in settings.ENABLED_SUBJECTS:
            raise CommandError('Subject {0} is not enabled'.format(subject))

        subject = Subject.objects.get(name=subject)
        ma, mi, pa = helpers.get_version_components(release)
        release = Release.objects.get(
                subject=subject, major=ma, minor=mi, patch=pa
            )
        subject = subjects.SubjectCreator.from_subject(subject)
        subject.initialize(release)
        subject.gprof(index)
