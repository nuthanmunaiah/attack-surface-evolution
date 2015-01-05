import csv, datetime
from django.utils import unittest
from django.test import TestCase

from app.models import *
from app.management.commands import initdb, loaddb
from app import get_absolute_path


class InitDbTestCase(TestCase):
    def setUp(self):
        self.initdb_command = initdb.Command()

        revisions_file = get_absolute_path('assets\\data\\revisions.txt')

        self.revisions = dict()
        with open(revisions_file, 'r') as _revisions_file:
            reader = csv.reader(_revisions_file)
            for row in reader:
                self.revisions[row[0]] = row[1]

        cve_files = [get_absolute_path('assets\\data\\cves_reported.txt'),
                     get_absolute_path('assets\\data\\cves_non_ffmpeg.txt')]

        self.cves = dict()
        for cve_file in cve_files:
            with open(cve_file, 'r') as _cve_file:
                reader = csv.reader(_cve_file)
                for row in reader:
                    self.cves[row[0]] = row[1]

        cves_fixed_file = get_absolute_path('assets\\data\\cves_fixed.txt')

        self.fixed_cves = dict()
        with open(cves_fixed_file, 'r') as _cves_fixed_file:
            reader = csv.reader(_cves_fixed_file)
            for row in reader:
                if row[1] in self.fixed_cves:
                    self.fixed_cves[row[1]].append({'revision': row[0], 'commit_hash': row[2], 'publish_dt': row[3]})
                else:
                    self.fixed_cves[row[1]] = [{'revision': row[0], 'commit_hash': row[2], 'publish_dt': row[3]}]

    def test_load_revisions(self):
        self.initdb_command.load_revisions()
        self.assertEqual(Revision.objects.all().count(), len(self.revisions))

        for revision in self.revisions:
            db_revision = Revision.objects.get(number=revision)
            self.assertEqual(datetime.datetime.strptime(self.revisions[revision], '%m/%d/%Y').date(), db_revision.date)

    def test_load_cves(self):
        self.initdb_command.load_cves()
        self.assertEqual(Cve.objects.all().count(), len(self.cves))

        for cve in self.cves:
            db_cve = Cve.objects.get(cve_id=cve)
            self.assertEqual(datetime.datetime.strptime(self.cves[cve], '%m/%d/%Y').date(), db_cve.publish_dt)

    def test_map_cves_to_revisions(self):
        self.initdb_command.map_cves_to_revisions()

        for cve in Cve.objects.all():
            self.assertEqual(cve.is_fixed, cve in self.fixed_cves)
            if cve.is_fixed:
                self.assertEqual(len(self.fixed_cves[cve]), CveRevision.objects.filter(cve__cve_id=cve).count())