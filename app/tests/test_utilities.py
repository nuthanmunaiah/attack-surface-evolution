import os

from django.conf import settings
from django.test import TestCase

from app import utilities, errors
from app.subjects import ffmpeg
from app.models import Revision, Cve, CveRevision


class UtilitiesTestCase(TestCase):
    def setUp(self):
        pass

    def test_load_revisions(self):
        # Load
        utilities.load_revisions()

        # Test
        self.assertEqual(165, Revision.objects.filter(type='t').count())
        self.assertEqual(16, Revision.objects.filter(type='b').count())
        self.assertEqual(181, Revision.objects.all().count())

    def test_load_cves(self):
        # Load
        utilities.load_cves()

        # Test
        self.assertEqual(202, Cve.objects.all().count())

    def test_map_cve_to_revision(self):
        # Setup
        cves_count = {
            '2.5.0': 13, '2.4.4': 4, '2.4.2': 9, '2.3.5': 8,
            '2.3.4': 1, '2.3.3': 1, '2.3.2': 1, '2.3.0': 2,
            '2.2.11': 4, '2.2.9': 8, '2.2.7': 2, '2.2.4': 2,
            '2.2.0': 4, '2.1.6': 14, '2.1.5': 2, '2.1.4': 4,
            '2.1.0': 17, '2.0.6': 10, '2.0.5': 2, '2.0.4': 4,
            '2.0.3': 4, '2.0.2': 13, '2.0.1': 3, '2.0.0': 6,
            '1.2.9': 8, '1.2.8': 2, '1.2.7': 2, '1.2.6': 4,
            '1.2.5': 1, '1.2.4': 6, '1.2.3': 4, '1.2.1': 6,
            '1.2.0': 5, '1.1.14': 2, '1.1.12': 2, '1.1.9': 5,
            '1.1.8': 1, '1.1.7': 2, '1.1.6': 7, '1.1.5': 6,
            '1.1.4': 3, '1.1.3': 9, '1.1.2': 9, '1.1.1': 2,
            '1.1.0': 18, '1.0.10': 4, '1.0.9': 4, '1.0.8': 6,
            '1.0.7': 5, '1.0.6': 2, '1.0.5': 8, '1.0.4': 11,
            '1.0.2': 2, '1.0.1': 11, '0.11.5': 7, '0.11.4': 5,
            '0.11.3': 3, '0.11.0': 31, '0.10.15': 6, '0.10.14': 2,
            '0.10.13': 1, '0.10.12': 4, '0.10.9': 6, '0.10.7': 4,
            '0.10.6': 18, '0.10.3': 4, '0.10.0': 30, '0.9.4': 6,
            '0.9.3': 7, '0.9.1': 24, '0.8.15': 1, '0.8.11': 15,
            '0.8.10': 4, '0.8.7': 6, '0.8.6': 1, '0.8.5': 1,
            '0.7.16': 1, '0.7.12': 16, '0.7.11': 4, '0.7.8': 6,
            '0.7.7': 1, '0.7.6': 1, '0.7.0': 1, '0.6.5': 5,
            '0.6.4': 7, '0.6.2': 1, '0.5.14': 5, '0.5.13': 2,
            '0.5.11': 5, '0.5.8': 5, '0.5.7': 3, '0.5.6': 2,
            '0.5.5': 4, '0.5.4': 11, '0.5.0': 3
        }

        cve_fix_commit_hashes = [
            {
                'revision': '2.5.0', 'cve': 'CVE-2014-8541',
                'commit_hash': '5c378d6a6df8243f06c87962b873bd563e58cd39'
            },
            {
                'revision': '2.4.4', 'cve': 'CVE-2014-9316',
                'commit_hash': '8524009161b0430ba961a4e6fcd8125a695edd7c'
            },
            {
                'revision': '2.3.4', 'cve': 'CVE-2014-8541',
                'commit_hash': '57bdb3f3dde3de7e84c888ae205574873bd1787b'
            },
            {
                'revision': '2.2.9', 'cve': 'CVE-2014-8541',
                'commit_hash': '6287107eae40750f47ec3888c52fd94a9c697b38'
            },
            {
                'revision': '2.1.5', 'cve': 'CVE-2014-4609',
                'commit_hash': '9c358c6e3b3422b209c3fea18313bd33229c0858'
            },
            {
                'revision': '2.0.4', 'cve': 'CVE-2014-2098',
                'commit_hash': '13ce3673684e0fe69964f71660747e674c1f524c'
            },
            {
                'revision': '1.2.9', 'cve': 'CVE-2014-8544',
                'commit_hash': 'f56095c4d7e5a76be8b114bcf427ab0becf0c635'
            },
            {
                'revision': '1.1.8', 'cve': 'CVE-2013-7008',
                'commit_hash': 'a4b705b4cbb57c1cc32d6e368e0176510ef3c2e3'
            },
            {
                'revision': '1.0.8', 'cve': 'CVE-2013-7021',
                'commit_hash': '11586b077e6e81bc390b6df657429b4a39741d2f'
            },
            {
                'revision': '0.11.3', 'cve': 'CVE-2013-0868',
                'commit_hash': '562aa82d2a22cba39caede1d7b1243fdb6311ce5'
            },
            {
                'revision': '0.10.12', 'cve': 'CVE-2014-2263',
                'commit_hash': '68b14c044a4a00d69aeb620bdb57dce533c4190a'
            },
            {
                'revision': '0.9.3', 'cve': 'CVE-2013-0868',
                'commit_hash': '21dd8f5baa43d852354e9b6d8174be4095cdec0e'
            },
            {
                'revision': '0.5.11', 'cve': 'CVE-2013-0849',
                'commit_hash': 'fee26d352a52eb9f7fcd8d9167fb4a5ba015b612'
            },
        ]

        # Load
        utilities.load_revisions()
        utilities.load_cves()
        utilities.map_cve_to_revision()

        # Test
        self.assertEqual(170, Cve.objects.filter(is_fixed=True).count())

        for revision in cves_count:
            self.assertEqual(
                cves_count[revision],
                CveRevision.objects.filter(
                    revision__number=revision,
                    revision__type='t'
                ).count(),
                msg='%s' % revision
            )

        for item in cve_fix_commit_hashes:
            self.assertEqual(
                1,
                CveRevision.objects.filter(
                    revision__number=item['revision'],
                    cve__cve_id=item['cve'],
                    commit_hash=item['commit_hash'],
                    revision__type='t'
                ).count()
            )

    def test_process_revision(self):
        pass

    def test_process_node(self):
        pass

    def tearDown(self):
        pass
