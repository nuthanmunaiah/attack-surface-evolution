import csv
import sys
import traceback

from datetime import datetime
from django.core.management.base import BaseCommand
from django.db import transaction

from app import constants, helpers, subjects
from app.models import *


class Command(BaseCommand):
    help = 'initdb HELP.'

    def handle(self, *args, **options):
        try:
            with transaction.atomic():
                self._load_subjects()
                self._load_branches()
                self._load_releases()
                self._load_cves()
                self._map_cve_to_release()
        except Exception as e:
            sys.stderr.write(
                'ERROR: initdb failed. All database changes aborted.\n'
            )
            extype, exvalue, extrace = sys.exc_info()
            traceback.print_exception(extype, exvalue, extrace)

    def _load_subjects(self):
        for (name, remote) in constants.SUBJECTS.items():
            print('Loading subject {0}'.format(name))

            subject = Subject(name=name, remote=remote)
            subject.save()

    def _load_branches(self):
        for name in constants.SUBJECTS:
            subject = Subject.objects.get(name=name)
            branches_file = helpers.get_absolute_path(
                'app/assets/data/{0}/branches.csv'.format(subject.name)
            )
            with open(branches_file, 'r') as _branches_file:
                reader = csv.reader(_branches_file)
                for row in reader:
                    print('Loading branch {0} of {1}'.format(
                        row[0], subject.name
                    ))

                    ma, mi, pa = helpers.get_version_components(row[0])

                    branch = Branch(
                        subject=subject, major=ma, minor=mi, reference=row[0],
                        configure_options=row[1]
                    )
                    branch.save()

    def _load_releases(self):
        for name in constants.SUBJECTS:
            subject = Subject.objects.get(name=name)
            branches = Branch.objects.filter(subject=subject)

            releases_file = helpers.get_absolute_path(
                'app/assets/data/{0}/revisions.csv'.format(subject.name)
            )
            with open(releases_file, 'r') as _releases_file:
                reader = csv.reader(_releases_file)
                for row in reader:
                    print('Loading revision {0} of {1}'.format(
                        row[0], subject.name
                    ))

                    ma, mi, pa = helpers.get_version_components(row[0])
                    branch = branches.get(major=ma, minor=mi)

                    release = Release(
                        subject=subject,
                        branch=branch,
                        date=row[2],
                        major=ma, minor=mi, patch=pa,
                        reference=row[1] if row[1] else row[0],
                    )
                    release.save()

    def _load_cves(self):
        for name in constants.SUBJECTS:
            subject = Subject.objects.get(name=name)
            cves_file = helpers.get_absolute_path(
                'app/assets/data/{0}/cves.csv'.format(subject.name)
            )
            with open(cves_file, 'r') as _cve_file:
                reader = csv.reader(_cve_file)
                for row in reader:
                    print('Loading CVE {0} of {1}'.format(
                        row[0], subject.name
                    ))
                    cve = Cve(
                        subject=subject,
                        identifier=row[0],
                        publish_dt=datetime.strptime(row[1], '%m/%d/%Y')
                    )
                    cve.save()

    def _map_cve_to_release(self):
        for name in constants.SUBJECTS:
            subject = Subject.objects.get(name=name)

            releases = Release.objects.filter(subject=subject)
            branches = Branch.objects.filter(subject=subject)
            cves = Cve.objects.filter(subject=subject)

            cves_fixed_file = helpers.get_absolute_path(
                'app/assets/data/{0}/cves_fixed.csv'.format(subject.name)
            )

            with open(cves_fixed_file, 'r') as _cves_fixed_file:
                reader = csv.reader(_cves_fixed_file)
                for row in reader:
                    ma, mi, pa = helpers.get_version_components(row[0])

                    branch = branches.get(major=ma, minor=mi)
                    cve = cves.get(identifier=row[1])
                    release = releases.get(major=ma, minor=mi, patch=pa)

                    cve_release = CveRelease(
                        cve=cve, release=release, fix_sha=row[2]
                    )
                    cve_release.save()

            _subject = subjects.SubjectCreator.from_subject(subject, '/tmp/')
            _subject.clone()
            for branch in branches:
                _subject.checkout(branch.reference)

                cve_releases = CveRelease.objects.filter(
                        release__branch=branch,
                    )

                for cve_release in cve_releases:
                    shas = [cve_release.fix_sha]
                    for (name, file_) in _subject.get_functions(shas):
                        vulnerability_fix = VulnerabilityFix(
                            cve_release=cve_release, name=name, file=file_
                        )
                        vulnerability_fix.save()
