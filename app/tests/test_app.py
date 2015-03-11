from django.test import TestCase

from app import *


class AppTestCase(TestCase):
    def test_get_version_number(self):
        self.assertEqual(get_version_number('1'), '1.0.0')
        self.assertEqual(get_version_number('0.1'), '0.1.0')
        self.assertEqual(get_version_number('0.0.1'), '0.0.1')
        self.assertEqual(get_version_number('1.00.1'), '1.0.1')
        self.assertEqual(get_version_number('00.01.00'), '0.1.0')
        self.assertEqual(get_version_number('0.1.00'), '0.1.0')
        self.assertRaises(InvalidVersion, get_version_number, 'a.b.c')
