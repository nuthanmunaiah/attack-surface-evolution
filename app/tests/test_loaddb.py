import os
from django.test import TestCase
from django.conf import settings
from django.core.management.base import CommandError

from attacksurfacemeter.call_graph import CallGraph

from app import gitapi, get_absolute_path
from app.models import Revision, Function
from app.management.commands import initdb, loaddb


class CommandTestCase(TestCase):
	def setUp(self):
		if not os.path.exists(settings.REPOSITORY_PATH):
			self.repo = gitapi.Repo.git_clone(
				settings.FFMPEG_CLONE_URL, settings.REPOSITORY_PATH
			)
		else:
			self.repo = gitapi.Repo(settings.REPOSITORY_PATH)

		# Initialize database
		command = initdb.Command()
		command.load_revisions()
		command.load_cves()
		command.map_cves_to_revisions()

		self.command = loaddb.Command()

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
			self.command.validate_arguments, **options)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': 'a.0.1',
			'rev_type': 't',
			'verbosity': 0
		}

		self.assertRaises(CommandError,
			self.command.validate_arguments, **options)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.0.1',
			'rev_type': 'c',
			'verbosity': 0
		}

		self.assertRaises(CommandError,
			self.command.validate_arguments, **options)

		# Scenario: Positive case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.0.1',
			'rev_type': 't',
			'verbosity': 0
		}

		self.assertIsNone(self.command.validate_arguments(**options))

	def test_get_call_graph(self):
		# Scenario: Negative case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.7.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.7.0', type='b')

		self.assertRaises(CommandError, self.command.get_call_graph, 
			revision)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.8.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.8.0', type='b')

		self.assertRaises(CommandError, self.command.get_call_graph, 
			revision)

		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.9.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.9.0', type='b')

		self.assertRaises(CommandError, self.command.get_call_graph, 
			revision)

		# Scenario: Positive case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.6.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.command.validate_arguments(**options)
		
		revision = Revision.objects.get(number='0.6.0', type='b')

		call_graph = self.command.get_call_graph(revision)
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
		self.command.validate_arguments(**options)
		
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

		actual = self.command.get_vulnerable_functions(revision)

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

		actual = self.command.get_vulnerable_functions(revision)

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
		self.command.validate_arguments(**options)
		revision = Revision.objects.get(number='0.7.0', type='b')

		self.assertRaises(CommandError,
			self.command.get_function_sloc, revision)

		# Scenario: Positive case(s)
		revision = Revision.objects.get(number='0.6.0', type='b')

		expected = {
			'start_children@ffserver.c': 45,
			'av_exit@ffmpeg.c': 53,
			# TODO: Uncomment after /attack-surface-metrics/issues/39 is
			# 	resolved
			#'bswap_32@bswap.h': 6,
		}

		actual = self.command.get_function_sloc(revision)

		for item in expected:
			self.assertEqual(actual[item], expected[item], msg=item)

	def test_mine(self):
		# Scenario: Positive case(s)
		options = {
			'repository_path': settings.REPOSITORY_PATH,
			'workspace_path': get_absolute_path('tests/data'),
			'rev_num': '0.6.0',
			'rev_type': 'b',
			'verbosity': 0
		}
		self.command.validate_arguments(**options)
		revision = Revision.objects.get(number='0.6.0', type='b')

		self.command.mine(revision)

		self.assertEqual(revision.num_functions, 7538)
		self.assertEqual(revision.num_entry_points, 32)
		self.assertEqual(
			Function.objects.filter(revision=revision, is_entry=True).count(),
			32
		)
		self.assertEqual(revision.num_exit_points, 297)
		self.assertEqual(
			Function.objects.filter(revision=revision, is_exit=True).count(),
			297
		)

		expected = {
			'gifdec.c': set(['svq1_decode_frame']),
			'vmdav.c': set(['lz_unpack','rle_unpack', 'vmd_decode']),
			'vp5.c': set(['vp5_parse_coeff']),
			'vp6.c': set(['vp6_parse_coeff']),
			'vp3.c': set(['vp3_dequant', 'render_slice']),
			'qdm2.c': set(['qdm2_decode_init', 'qdm2_decode']),
			'ape.c': set(['ape_read_header']),
			'vorbis_dec.c': set([
				'vorbis_parse_setup_hdr_residues', 
				'vorbis_parse_audio_packet','vorbis_residue_decode_internal'
			]),
			'matroskadec.c': set(['matroska_convert_tags']),
			# TODO: Uncomment when render_line_unrolled is figured out
			# 'vorbis.c': set(['ff_vorbis_ready_floor1_list', 'render_line', 
			# 	'ff_vorbis_floor1_render_list','render_line_unrolled']),
			# TODO: Remove when render_line_unrolled is figured out
			'vorbis.c': set(['ff_vorbis_ready_floor1_list', 'render_line', 
				'ff_vorbis_floor1_render_list']),
			'vp3.c': set(['unpack_vlcs', 'unpack_dct_coeffs']),
			# TODO: Uncomment when av_image_fill_pointers is figured out
			# 'imgutils.c': set(['av_image_fill_pointers']),
		}

		vulnerable_functions = Function.objects.filter(
			revision=revision, is_vulnerable=True
		)

		actual = {}
		for vulnerable_function in vulnerable_functions:
			if vulnerable_function.file not in actual:
				actual[vulnerable_function.file] = set()
			actual[vulnerable_function.file].add(vulnerable_function.name)

		self.assertEqual(len(actual), len(expected))
		self.assertTrue(all(item in actual for item in expected))
		for item in expected:
			self.assertEqual(len(actual[item]), len(expected[item]), msg=item)
			self.assertTrue(item in actual[item] for item in expected[item])

		# TODO: Test reachability and vulnerability source and sink
