import os
from django.test import TestCase
from django.conf import settings
from django.core.management.base import CommandError

from attacksurfacemeter.call_graph import CallGraph

from .. import gitapi, get_absolute_path
from ..models import Revision
from ..management.commands import initdb, loaddb


class LoadDBTestCase(TestCase):
	def setUp(self):
		if not os.path.exists(settings.REPOSITORY_PATH):
			self.repo = gitapi.Repo.git_clone(
				settings.FFMPEG_CLONE_URL, settings.REPOSITORY_PATH
			)
		else:
			self.repo = gitapi.Repo(settings.REPOSITORY_PATH)

		# Initialize database
		initdb_command = initdb.InitDBCommand()
		initdb_command.load_revisions()
		initdb_command.load_cves()
		initdb_command.map_cves_to_revisions()

		self.loaddb_command = loaddb.LoadDBCommand()

	def test_validate_arguments(self):
		# Scenario: Negative case(s)
		options = {
			'repository_path': '/',
			'workspace_path': '/',
			'rev_num': '0.0.1',
			'rev_type': 't',
			'verbosity': 0
		}

		self.assertRaises(CommandError,
			self.loaddb_command.validate_arguments, **options)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': 'a.0.1',
			'rev_type': 't',
			'verbosity': 0
		}

		self.assertRaises(CommandError,
			self.loaddb_command.validate_arguments, **options)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.0.1',
			'rev_type': 'c',
			'verbosity': 0
		}

		self.assertRaises(CommandError,
			self.loaddb_command.validate_arguments, **options)

		# Scenario: Positive case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.0.1',
			'rev_type': 't',
			'verbosity': 0
		}

		self.assertIsNone(self.loaddb_command.validate_arguments(**options))

	def test_get_call_graph(self):
		# Scenario: Negative case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.7.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.loaddb_command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.7.0', type='b')

		self.assertRaises(CommandError, self.loaddb_command.get_call_graph, 
			revision)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.8.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.loaddb_command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.8.0', type='b')

		self.assertRaises(CommandError, self.loaddb_command.get_call_graph, 
			revision)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.9.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.loaddb_command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.9.0', type='b')

		self.assertRaises(CommandError, self.loaddb_command.get_call_graph, 
			revision)

		# Scenario: Positive case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.6.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.loaddb_command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.6.0', type='b')

		call_graph = self.loaddb_command.get_call_graph(revision)
		self.assertTrue(isinstance(call_graph, CallGraph))

	def test_get_vulnerable_functions(self):
		# Scenario: Positive case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '2.2.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.loaddb_command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='2.2.0', type = 'b')

		expected = {
			'mjpegdec.c': set(['mjpeg_decode_app', 'ff_mjpeg_decode_dht',
				'ff_mjpeg_decode_sof']),
			'pngdec.c': set(['decode_frame']),
			'rawdec.c': set(['raw_init_decoder']),
			'hevc_ps.c': set(['ff_hevc_decode_nal_sps']),
			'utils.c': set(['avcodec_align_dimensions2']),
			'mmvideo.c': set(['mm_decode_intra']),
			'tiff.c': set(['tiff_decode_tag']),
			'cinepak.c': set(['cinepak_decode_vectors']),
			'gifdec.c': set(['gif_read_image']),
			'iff.c': set(['decode_frame']),
			'proresenc_kostya.c': set(['encode_slice','encode_frame']),
			'lzo.c': set(['get_len']),
			'mpegtsenc.c': set(['mpegts_write_pat', 'mpegts_write_pmt']),
			'msrle.c': set(['msrle_decode_frame']),
			'takdec.c': set(['tak_decode_frame']),
			'wmalosslessdec.c': set([]),
			'smc.c': set([]),
		}

		actual = self.loaddb_command.get_vulnerable_functions(revision)

		for item in actual:
			if item not in expected:
				print(item, actual[item])

		self.assertEqual(len(actual), len(expected))
		self.assertTrue(all(item in actual for item in expected))
		for item in expected:
			self.assertEqual(len(actual[item]), len(expected[item]), msg=item)
			self.assertTrue(item in actual[item] for item in expected[item])

		revision = Revision.objects.get(number='2.2.9', type = 't')

		expected = {
			'gifdec.c': set(['gif_read_image']),
			'cinepak.c': set(['cinepak_decode_vectors']),
			'mmvideo.c': set(['mm_decode_intra']),
			'smc.c': set([]),
			'utils.c': set(['avcodec_align_dimensions2']),
			'pngdec.c': set(['decode_frame']),
			'mjpegdec.c': set(['ff_mjpeg_decode_dht', 'ff_mjpeg_decode_sof']),
			'tiff.c': set(['tiff_decode_tag']),
		}

		actual = self.loaddb_command.get_vulnerable_functions(revision)

		for item in actual:
			if item not in expected:
				print(item, actual[item])

		self.assertEqual(len(actual), len(expected))
		self.assertTrue(all(item in actual for item in expected))
		for item in expected:
			self.assertEqual(len(actual[item]), len(expected[item]), msg=item)
			self.assertTrue(item in actual[item] for item in expected[item])

	def test_get_function_sloc(self):
		# Scenario: Negative case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.6.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.loaddb_command.validate_arguments(**options)
		revision = Revision.objects.get(number='0.7.0', type='b')

		self.assertRaises(CommandError,
			self.loaddb_command.get_function_sloc, revision)

		# Scenario: Positive case(s)
		revision = Revision.objects.get(number='0.6.0', type='b')

		expected = {
			'start_children@ffserver.c': 45,
			'av_exit@ffmpeg.c': 53,
			# TODO: Uncomment after /attack-surface-metrics/issues/39 is
			# 	resolved
			#'bswap_32@bswap.h': 6,
		}

		actual = self.loaddb_command.get_function_sloc(revision)

		for item in expected:
			self.assertEqual(actual[item], expected[item], msg=item)

	def test_mine(self):
		pass
