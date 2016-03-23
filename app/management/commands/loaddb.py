from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from app import constants, helpers, subjects, utilities
from app.errors import InvalidVersionError
from app.models import *


def check_release(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        try:
            ma, mi, pa = helpers.get_version_components(value)
            releases = Release.objects.filter(major=ma, minor=mi, patch=pa)

            if not releases.exists():
                raise OptionValueError(
                    'Release %s does not exist in the database.' % value
                )
        except InvalidVersionError:
            raise OptionValueError(
                'Invalid release number specified. %s must be formatted as '
                '0.0.0' % opt_str
            )


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option(
            '-s', choices=list(constants.SUBJECTS.keys()), dest='subject',
            help='Name of the subject to load the database with.'
        ),
        make_option(
            '-r', type='str', action='callback', callback=check_release,
            dest='release',
            help=(
                'Release number of the subject to load the database with, '
                'e.g. 2.6.0. Default is None, in which case all releasess of'
                ' the subject are loaded.'
            )
        ),
        make_option(
            '-p', type='int', dest='processes',
            default=settings.PARALLEL['SUBPROCESSES'],
            help='Number of processes to spawn when loading a release.',
        )
    )

    help = (
        'Collects attack surface metrics from a specified release of a '
        'software system.'
    )

    def handle(self, *args, **options):
        subject = options['subject']
        release = options['release']
        processes = options['processes']

        if subject not in settings.ENABLED_SUBJECTS:
            raise CommandError('Subject {0} is not enabled'.format(subject))

        subject = Subject.objects.get(name=subject)
        releases = Release.objects.filter(subject=subject, is_loaded=False)
        subject = subjects.SubjectCreator.from_subject(subject)

        if release:
            ma, mi, pa = helpers.get_version_components(release)
            release = releases.get(major=ma, minor=mi, patch=pa)

        subject.initialize(release)
        utilities.load(subject, processes)
