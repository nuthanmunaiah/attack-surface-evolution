import csv
import os
import sys
import traceback

from datetime import datetime
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from app import constants, helpers
from app.models import *
from app.subjects import SubjectCreator


class Command(BaseCommand):
    help = 'initdb HELP.'

    def handle(self, *args, **options):
        try:
            with transaction.atomic():
                subjects = self._load_subjects()
                self._load_branches(subjects)
                self._load_releases(subjects)
                self._load_cves(subjects)
                self._map_cve_to_release(subjects)
                self._load_vulnerability_fix_overrides(subjects)
        except Exception as e:
            sys.stderr.write(
                'ERROR: initdb failed. All database changes aborted.\n'
            )
            extype, exvalue, extrace = sys.exc_info()
            traceback.print_exception(extype, exvalue, extrace)

    def _load_subjects(self):
        subjects = list()

        for (name, remote) in constants.SUBJECTS.items():
            if Subject.objects.filter(name=name, remote=remote).exists():
                print('Subject {} already loaded'.format(name))
            elif name not in settings.ENABLED_SUBJECTS:
                print('Subject {} not enabled'.format(name))
            else:
                print('Loading subject {}'.format(name))

                subject = Subject(name=name, remote=remote)
                subject.save()
                subjects.append(subject)

        return subjects

    def _load_branches(self, subjects):
        for subject in subjects:
            branches_file = helpers.get_absolute_path(
                'app/assets/data/{}/branches.csv'.format(subject.name)
            )
            with open(branches_file, 'r') as _branches_file:
                reader = csv.reader(_branches_file)
                for row in reader:
                    print('Loading branch {} of {}'.format(
                        row[0], subject.name
                    ))

                    ma, mi, pa = helpers.get_version_components(row[0])

                    branch = Branch(
                        subject=subject, major=ma, minor=mi, reference=row[0],
                        configure_options=row[1]
                    )
                    branch.save()

    def _load_releases(self, subjects):
        for subject in subjects:
            branches = Branch.objects.filter(subject=subject)

            releases_file = helpers.get_absolute_path(
                'app/assets/data/{}/releases.csv'.format(subject.name)
            )
            with open(releases_file, 'r') as _releases_file:
                reader = csv.reader(_releases_file)
                for row in reader:
                    print('Loading release {} of {}'.format(
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

    def _load_cves(self, subjects):
        for subject in subjects:
            cves_file = helpers.get_absolute_path(
                'app/assets/data/{}/cves.csv'.format(subject.name)
            )
            with open(cves_file, 'r') as _cve_file:
                reader = csv.reader(_cve_file)
                for row in reader:
                    print('Loading CVE {} of {}'.format(row[0], subject.name))
                    cve = Cve(
                        subject=subject,
                        identifier=row[0],
                        publish_dt=datetime.strptime(row[1], '%m/%d/%Y')
                    )
                    cve.save()

    def _map_cve_to_release(self, subjects):
        for subject in subjects:
            releases = Release.objects.filter(subject=subject)
            branches = Branch.objects.filter(subject=subject)
            cves = Cve.objects.filter(subject=subject)

            cves_fixed_file = helpers.get_absolute_path(
                'app/assets/data/{}/cves_fixed.csv'.format(subject.name)
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

            _subject = SubjectCreator.from_subject(subject)
            _subject.clone()
            for branch in branches:
                _subject.checkout(branch.reference, force=True)

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

    def _load_vulnerability_fix_overrides(self, subjects):
        for subject in subjects:
            overrides_file = helpers.get_absolute_path(
                'app/assets/data/{}/vulnerability_fix_overrides.csv'.format(
                    subject.name
                )
            )

            if not os.path.exists(overrides_file):
                continue

            with open(overrides_file, 'r') as _overrides_file:
                reader = csv.reader(_overrides_file)
                for row in reader:
                    print('Loading vulnerability fix override for {}'.format(
                        row[1],
                    ))

                    ma, mi, pa = helpers.get_version_components(row[0])
                    release = Release.objects.get(
                        subject=subject, major=ma, minor=mi, patch=pa
                    )
                    cve_release = CveRelease.objects.get(
                        release=release, fix_sha=row[2],
                        cve__subject=subject, cve__identifier=row[1]
                    )
                    vulnerability_fix = VulnerabilityFix(
                        cve_release=cve_release, name=row[3], file=row[4]
                    )
                    vulnerability_fix.save()
