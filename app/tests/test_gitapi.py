import hashlib
import shutil
import os
from django.test import TestCase
from django.conf import settings

from app import gitapi


class RepoTestCase(TestCase):
    def setUp(self):
        self.repository_path = '/tmp/.FFmpeg/'
        if not os.path.exists(self.repository_path):
            self.repo = gitapi.Repo.git_clone(
                'https://github.com/FFmpeg/FFmpeg.git', self.repository_path
            )
        else:
            self.repo = gitapi.Repo(self.repository_path)

    def test_git_patch(self):
        # Scenario: No file filter
        self.assertEqual(
            hashlib.md5(
                self.repo.git_patch(
                    'c0cbe36b18ab3eb13a53fe684ec1f63a00df2c86'
                ).encode()
            ).hexdigest(),
            'f40607119c0c0de98173ecbbc2307ce9'
        )

        self.assertEqual(
            hashlib.md5(
                self.repo.git_patch(
                    '0af49a63c7f87876486ab09482d5b26b95abce60'
                ).encode()
            ).hexdigest(),
            'a096978f32b4422d60816ce439319d7f'
        )

        # Scenario: File filter applied
        self.assertEqual(
            hashlib.md5(
                self.repo.git_patch(
                    '1bf2461765c58aad5829ea45a2885d11f50b73f0',
                    file='libavfilter/vf_boxblur.c'
                ).encode()
            ).hexdigest(),
            'c3d9d648e72dcc42af70abd8ded00b16'
        )

        self.assertEqual(
            hashlib.md5(
                self.repo.git_patch(
                    '13451f5520ce6b0afde861b2285dda659f8d4fb4',
                    file='libavcodec/atrac3.c'
                ).encode()
            ).hexdigest(),
            '155267e42b77755b993397b38192dfa0'
        )

        self.assertEqual(
            hashlib.md5(
                self.repo.git_patch(
                    '1bf2461765c58aad5829ea45a2885d11f50b73f0',
                    file='libavcodec/atrac3.c'
                ).encode()
            ).hexdigest(),
            '217d69d77c47e3340fb9e316be9bd280'
        )

    def test_git_diff_tree(self):
        # Scenario: Multiple files
        expected = (
            'libavfilter/vf_boxblur.c\n'
            'libavfilter/vf_delogo.c\n'
            'libavfilter/vf_fieldmatch.c\n'
            'libavfilter/vf_fieldorder.c\n'
            'libavfilter/vf_gradfun.c\n'
            'libavfilter/vf_hflip.c\n'
            'libavfilter/vf_kerndeint.c\n'
            'libavfilter/vf_lut.c\n'
            'libavfilter/vf_pad.c\n'
            'libavfilter/vf_showinfo.c\n'
            'libavfilter/vf_vignette.c\n'
        )
        actual = self.repo.git_diff_tree(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0'
        )
        self.assertEqual(actual, expected)

        expected = (
            'libavfilter/vf_boxblur.c\n'
            'libavfilter/vf_delogo.c\n'
            'libavfilter/vf_fieldorder.c\n'
            'libavfilter/vf_gradfun.c\n'
            'libavfilter/vf_hflip.c\n'
            'libavfilter/vf_kerndeint.c\n'
            'libavfilter/vf_lut.c\n'
            'libavfilter/vf_pad.c\n'
            'libavfilter/vf_showinfo.c\n'
        )
        actual = self.repo.git_diff_tree(
            '64d362fce718d5dfe108c147971ca9558f5bed24'
        )
        self.assertEqual(actual, expected)

        # Scenario: Single file
        expected = 'libavcodec/vmdav.c\n'
        actual = self.repo.git_diff_tree(
            'c0cbe36b18ab3eb13a53fe684ec1f63a00df2c86'
        )
        self.assertEqual(actual, expected)

        expected = 'libavformat/avidec.c\n'
        actual = self.repo.git_diff_tree(
            '0af49a63c7f87876486ab09482d5b26b95abce60'
        )
        self.assertEqual(actual, expected)

    def test_get_files_changed(self):
        # Scenario: Multiple files
        expected = [
            'libavfilter/vf_boxblur.c',
            'libavfilter/vf_delogo.c',
            'libavfilter/vf_fieldmatch.c',
            'libavfilter/vf_fieldorder.c',
            'libavfilter/vf_gradfun.c',
            'libavfilter/vf_hflip.c',
            'libavfilter/vf_kerndeint.c',
            'libavfilter/vf_lut.c',
            'libavfilter/vf_pad.c',
            'libavfilter/vf_showinfo.c',
            'libavfilter/vf_vignette.c',
        ]
        actual = self.repo.get_files_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'libavfilter/vf_boxblur.c',
            'libavfilter/vf_delogo.c',
            'libavfilter/vf_fieldorder.c',
            'libavfilter/vf_gradfun.c',
            'libavfilter/vf_hflip.c',
            'libavfilter/vf_kerndeint.c',
            'libavfilter/vf_lut.c',
            'libavfilter/vf_pad.c',
            'libavfilter/vf_showinfo.c',
        ]
        actual = self.repo.git_diff_tree(
            '64d362fce718d5dfe108c147971ca9558f5bed24'
        )
        self.assertTrue(all(item in actual for item in expected))

        # Scenario: Single file
        expected = 'libavcodec/vmdav.c',
        actual = self.repo.git_diff_tree(
            'c0cbe36b18ab3eb13a53fe684ec1f63a00df2c86'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = 'libavformat/avidec.c',
        actual = self.repo.git_diff_tree(
            '0af49a63c7f87876486ab09482d5b26b95abce60'
        )
        self.assertTrue(all(item in actual for item in expected))

    def test_get_functions_changed(self):
        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_boxblur.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_delogo.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'copy_fields'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_fieldmatch.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_gradfun.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_hflip.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_kerndeint.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_lut.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_pad.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_showinfo.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        expected = [
            'filter_frame'
        ]
        actual = self.repo.get_functions_changed(
            '1bf2461765c58aad5829ea45a2885d11f50b73f0',
            file='libavfilter/vf_vignette.c'
        )
        self.assertTrue(all(item in actual for item in expected))

        # Scenario: File specified was not changed by the commit
        expected = []
        actual = self.repo.get_functions_changed(
            'e2291ea1534d17306f685b8c8abc8585bbed87bf',
            file='libavfilter/vf_vignette.c'
        )
        self.assertTrue(all(item in actual for item in expected))

    def tearDown(self):
        shutil.rmtree(self.repository_path)
