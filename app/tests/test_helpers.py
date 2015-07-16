import os

from django.conf import settings
from django.test import TestCase

from app import helpers, errors


class HelpersTestCase(TestCase):
    def setUp(self):
        pass

    def test_get_version_components(self):
        self.assertRaises(
            errors.InvalidVersionError,
            helpers.get_version_components, 'a.b.c'
        )

        self.assertEqual(
            helpers.get_version_components('1'),
            (1, 0, 0)
        )
        self.assertEqual(
            helpers.get_version_components('0.1'),
            (0, 1, 0)
        )
        self.assertEqual(
            helpers.get_version_components('0.0.1'),
            (0, 0, 1)
        )
        self.assertEqual(
            helpers.get_version_components('1.00.1'),
            (1, 0, 1)
        )
        self.assertEqual(
            helpers.get_version_components('00.01.00'),
            (0, 1, 0)
        )
        self.assertEqual(
            helpers.get_version_components('0.1.00'),
            (0, 1, 0)
        )
        self.assertEqual(
            helpers.get_version_components('refs/tags/n2.2.10'),
            (2, 2, 10)
        )
        self.assertEqual(
            helpers.get_version_components('refs/remotes/origin/release/2.5'),
            (2, 5, 0)
        )

        self.assertEqual(
            helpers.get_version_components('0_1'),
            (0, 1, 0)
        )
        self.assertEqual(
            helpers.get_version_components('0_0_1'),
            (0, 0, 1)
        )
        self.assertEqual(
            helpers.get_version_components('1_00_1'),
            (1, 0, 1)
        )
        self.assertEqual(
            helpers.get_version_components('00_01_00'),
            (0, 1, 0)
        )
        self.assertEqual(
            helpers.get_version_components('0_1_00'),
            (0, 1, 0)
        )
        self.assertEqual(
            helpers.get_version_components('refs/tags/curl-7_30_0'),
            (7, 30, 0)
        )

    def test_get_absolute_path(self):
        self.assertEqual(
            os.path.join(settings.BASE_DIR, 'app/data/assets'),
            helpers.get_absolute_path('app/data/assets')
        )

        self.assertEqual(
            os.path.join(settings.BASE_DIR, 'app/templates/app/base.html'),
            helpers.get_absolute_path('app/templates/app/base.html')
        )

    def tearDown(self):
        pass
