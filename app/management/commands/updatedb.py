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
            help='Name of the subject to update in the database.'
        ),
        make_option(
            '-r', type='str', action='callback', callback=check_release,
            dest='release',
            help=(
                'Release number of the subject to update in the database, '
                'e.g. 2.6.0.'
            )
        ),
        make_option(
            '-f', type='str', action='store', dest='field',
            help='Name of the database field to update.'
        ),
    )

    help = (
        'Update particular metric in the database for a specified release of '
        'a software system.'
    )

    def handle(self, *args, **options):
        subject = options['subject']
        release = options['release']
        field = options['field']

        if not release:
            raise CommandError('Release number cannot be left empty')
        if not field:
            raise CommandError('Parameter field cannot be left empty')
        if subject not in settings.ENABLED_SUBJECTS:
            raise CommandError('Subject {0} is not enabled'.format(subject))

        subject = Subject.objects.get(name=subject)
        ma, mi, pa = helpers.get_version_components(release)
        release = Release.objects.get(
                subject=subject, major=ma, minor=mi, patch=pa, is_loaded=True
            )
        subject = subjects.SubjectCreator.from_subject(subject)

        subject.initialize(release)
        if 'page_rank' in field:
            utilities.update_pagerank(subject)
        elif 'sloc' in field:
            utilities.update_sloc(subject)
        else:
            raise CommandError('Updating {0} is not supported'.format(field))
