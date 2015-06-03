from optparse import make_option, OptionValueError
from django.core.management.base import BaseCommand
from django.db.models import Q

from app.errors import InvalidVersionError
from app.models import Revision
from app.helpers import get_version_components
from app.subjects.ffmpeg import FFmpeg
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
            '-r', type='str', action='callback', callback=check_revision,
            dest='revision'
        ),
        make_option(
            '-i', type='int', action='store', dest='index'
        ),
        make_option(
            '-o', type='int', action='store', dest='offset', default=0
        ),
    )
    help = (
        'Generates gprof.txt file for a corresponding gmon.out file.'
    )

    def handle(self, *args, **options):
        revisions = Revision.objects.filter(type='b', is_loaded=False)

        if options['revision']:
            revisions = revisions.filter(number=options['revision'])
        else:
            # Versions 0.5.0 and 0.6.0 are being excluded because these
            # versions do not support FATE
            revisions = revisions.exclude(
                Q(number='0.5.0') | Q(number='0.6.0')
            )

        index = options.get('index', None)
        if index is not None:
            index += options.get('offset', 0)

        for revision in revisions:
            profile(revision, FFmpeg, index)
