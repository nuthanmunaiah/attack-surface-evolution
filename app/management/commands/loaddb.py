from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from app import constants, helpers, subjects, utilities
from app.errors import InvalidVersionError
from app.models import *


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
            '-s', choices=list(constants.SUBJECTS.keys()), dest='subject',
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
        make_option(
            '-p', type='int', dest='processes',
            default=settings.PARALLEL['SUBPROCESSES'],
            help='Number of processes to spawn when loading a revision.',
        )
    )

    help = (
        'Clone, checkout, build, test, and profile revisions of a '
        'subject. The profile information is used to measure the attack '
        'surface of the software. All metrics captured during the measurement'
        ' are then stored to the database by this command.'
    )

    def handle(self, *args, **options):
        subject = options['subject']
        release = options['revision']
        processes = options['processes']
        
        if subject not in settings.ENABLED_SUBJECTS:
            raise CommandError('Subject {0} is not enabled'.format(subject))

        subject = Subject.objects.get(name=subject)
        releases = Release.objects.filter(subject=subject, is_loaded=False)
        subject = subjects.SubjectCreator.from_subject(subject)

        if release:
            ma, mi, pa = helpers.get_version_components(release)
            releases = releases.filter(major=ma, minor=mi, patch=pa)

        for release in releases:
            utilities.load(release, subject, processes)
