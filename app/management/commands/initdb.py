import os, re, csv, datetime, re
from optparse import make_option
from django.db import transaction
from django.core.management.base import BaseCommand, CommandError

from app import get_absolute_path, get_version_number
from app.models import *

REV_NUM_RE = re.compile('^(\d{1,2}).(\d{1,2}).(\d{1,2})$')


class Command(BaseCommand):
    # TODO: Add help text to the options.
    option_list = BaseCommand.option_list + (
        make_option('-r', '--reset',
                    dest='reset',
                    action='store_true',
                    default=False,
                    help='reset HELP.'),
    )
    help = 'initdb HELP.'

    def handle(self, *args, **options):
        self.verbosity = int(options.get('verbosity'))
        self.reset = bool(options.get('reset'))

        if self.reset:
            self.write('Reseting database')
            Revision.objects.all().delete()
            Cve.objects.all().delete()

        self.load_revisions()
        self.load_cves()
        self.map_cves_to_revisions()

    def load_revisions(self):
        revisions_file = get_absolute_path('assets/data/revisions.txt')

        with transaction.atomic():
            with open(revisions_file, 'r') as _revisions_file:
                reader = csv.reader(_revisions_file)
                for row in reader:
                    if not Revision.objects.filter(number=row[0]).exists():
                        revision = Revision()
                        revision.number = get_version_number(row[1])
                        revision.type = row[0]
                        revision.ref = row[1]
                        revision.date = datetime.datetime.strptime(row[2], '%Y-%m-%d').date()
                        revision.save()

    def load_cves(self):
        cve_files = [get_absolute_path('assets/data/cves_reported.txt'),
                     get_absolute_path('assets/data/cves_non_ffmpeg.txt')]

        with transaction.atomic():
            for cve_file in cve_files:
                with open(cve_file, 'r') as _cve_file:
                    reader = csv.reader(_cve_file)
                    for row in reader:
                        cve = Cve()
                        cve.cve_id = row[0]
                        cve.publish_dt = datetime.datetime.strptime(row[1], '%m/%d/%Y')
                        cve.save()

    def map_cves_to_revisions(self):
        cves_fixed_file = get_absolute_path('assets/data/cves_fixed.txt')

        fixed_cves = dict()
        with open(cves_fixed_file, 'r') as _cves_fixed_file:
            reader = csv.reader(_cves_fixed_file)
            for row in reader:
                if row[1] in fixed_cves:
                    fixed_cves[row[1]].append({'revision': row[0], 'commit_hash': row[2]})
                else:
                    fixed_cves[row[1]] = [{'revision': row[0], 'commit_hash': row[2]}]

        with transaction.atomic():
            for cve in Cve.objects.all():
                if cve.cve_id in fixed_cves:
                    with transaction.atomic():
                        cve.is_fixed = True
                        cve.save()

                        for cve_fix in fixed_cves[cve.cve_id]:
                            rev_num = get_version_number(cve_fix['revision'])
                            cve_revision = CveRevision()
                            cve_revision.cve = cve
                            cve_revision.revision = Revision.objects.get(number=rev_num, type=constants.RT_TAG)
                            cve_revision.commit_hash = cve_fix['commit_hash']
                            cve_revision.save()

    def write(self, message, verbosity=1):
        if verbosity >= self.verbosity:
            self.stdout.write(str(message))