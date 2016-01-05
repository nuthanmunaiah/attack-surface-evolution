import os

from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from app import constants, helpers, subjects, utilities
from app.errors import InvalidVersionError
from app.models import *
from attacksurfacemeter.call import Call
from attacksurfacemeter.environments import Environments


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


def check_path(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value and not os.path.exists(value):
        raise OptionValueError('{0} is not a valid path'.format(value))


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
                'Release number of the subject to analyze metric sensitivity.'
            )
        ),
        make_option(
            '-i', type='int', action='store', dest='index',
            help=(
                'Index of the parameter set to use when computing the metric.'
            )
        ),
        make_option(
            '-f', type='str', action='callback', callback=check_path,
            dest='parameters_filepath',
            help=(
                'Path to the file containing the list of parameters to use '
                'during sensitivity analysis.'
            )
        ),
    )

    help = (
        'Analyze the sensitivity of a metric to differing set of parameters '
        'that are used when computing the value of the metric'
    )

    def handle(self, *args, **options):
        subject = options['subject']
        release = options['release']
        index = options['index']
        parameters_filepath = options['parameters_filepath']

        if subject not in settings.ENABLED_SUBJECTS:
            raise CommandError('Subject {0} is not enabled'.format(subject))

        subject = Subject.objects.get(name=subject)
        releases = Release.objects.filter(subject=subject, is_loaded=False)
        subject = subjects.SubjectCreator.from_subject(subject)

        if release:
            ma, mi, pa = helpers.get_version_components(release)
            release = releases.get(major=ma, minor=mi, patch=pa)

        with open(parameters_filepath) as file_:
            for (i, line) in enumerate(file_):
                if index == i:
                    line = line.strip('\n')
                    parameters = tuple(float(p) for p in line.split(','))

        subject.initialize(release)
        were_vuln = [
                Call(fix.name, fix.file, Environments.C)
                for fix in subject.release.past_vulnerability_fixes
            ]
        subject.load_call_graph(were_vuln)
        sensitivity = utilities.analyze_sensitivity(subject, parameters)
        print(sensitivity.p)
        print(sensitivity.d)
