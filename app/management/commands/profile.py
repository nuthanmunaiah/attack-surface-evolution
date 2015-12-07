from optparse import make_option, OptionValueError
from django.core.management.base import BaseCommand
from django.db.models import Q

from app import helpers, utilities, subjects
from app.errors import InvalidVersionError
from app.models import Release, Subject
from app.subjects import curl, ffmpeg


def check_revision(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        try:
            ma, mi, pa = helpers.get_version_components(value)
            releases = Release.objects.filter(
                version__major=ma, version__minor=mi, version__patch=pa
            )

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
            '-s', choices=constants.SUBJECTS, dest='subject'
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

        subject = Subject.objects.get(name=subject)
        ma, mi, pa = helpers.get_version_components(release)
        release = Release.objects.get(
                subject=subject,
                version__major=ma, version__minor=mi, version__patch=pa
            )
        subject = subjects.SubjectCreator.from_subject(subject)
        utilities.profile(release, subject, index)
