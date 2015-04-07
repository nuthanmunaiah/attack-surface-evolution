import os
import subprocess
import shutil
from django.test import TestCase
from hashlib import md5

from app import errors
from app.subjects.subject import Subject


class SubjectTestCase(TestCase):
	def setUp(self):
		pass

	def test_subject(self):
		subject = Subject('subject', 'https://github.com')

		self.assertEqual('subject', subject.name)
		self.assertEqual('https://github.com', subject.clone_url)
		self.assertIsNone(subject.git_reference)
		self.assertEqual('/tmp/subject', subject.scratch_dir)
		self.assertIsNone(subject.repo)
		
		uuid = md5(b'subject').hexdigest()
		self.assertEqual(uuid, subject.uuid)
		self.assertFalse(subject.prepared)
		self.assertFalse(subject.initialized)

		self.assertEqual(
			os.path.join('/tmp/subject', uuid, 'cflow.txt'),
			subject.cflow_file_path
		)
		self.assertEqual(
			os.path.join('/tmp/subject', uuid, 'gprof.txt'),
			subject.gprof_file_path
		)

		self.assertEqual(
			os.path.join('/tmp/subject', uuid, 'src'),
			subject.__source_dir__
		)

		self.assertFalse(subject.__cflow_file_exists__)
		self.assertFalse(subject.__gprof_file_exists__)
		self.assertFalse(subject.__clone_exists__)

		self.assertIsNone(subject.call_graph)
		self.assertIsNone(subject.function_sloc)
		self.assertIsNone(subject.vulnerable_functions)

	def test_clone(self):
		subject = Subject('backbone', 
			'https://github.com/jashkenas/backbone.git',)

		subject.clone()
		self.assertTrue(
			os.path.exists(os.path.join(subject.__source_dir__, '.git'))
		)
		shutil.rmtree(subject.scratch_dir)

	def test_checkout(self):
		subject = Subject('backbone', 
			'https://github.com/jashkenas/backbone.git',
			'remotes/origin/master')

		subject.clone()
		subject.checkout()

		process = subprocess.Popen(['git','branch'], stdout=subprocess.PIPE, 
			stderr=subprocess.PIPE, cwd=subject.__source_dir__)
		(out,err) = process.communicate()

		self.assertEqual('* (detached from origin/master)', 
			out.decode().split('\n')[0])

		shutil.rmtree(subject.scratch_dir)

	def test_configure(self):
		subject = Subject('subject', 'https://github.com')

		self.assertRaises(NotImplementedError, subject.configure)

	def test_test(self):
		subject = Subject('subject', 'https://github.com')

		self.assertRaises(NotImplementedError, subject.test)

	def test_cflow(self):
		subject = Subject('subject', 'https://github.com')

		self.assertRaises(NotImplementedError, subject.cflow)

	def test_gprof(self):
		subject = Subject('subject', 'https://github.com')

		self.assertRaises(NotImplementedError, subject.gprof)

	def test_initialize(self):
		subject = Subject('backbone', 
			'https://github.com/jashkenas/backbone.git',
			'remotes/origin/master')

		subject.initialize()
		self.assertTrue(subject.initialized)
		subject.initialize()

		shutil.rmtree(subject.scratch_dir)

	def test_prepare(self):
		subject = Subject('backbone', 
			'https://github.com/jashkenas/backbone.git',
			'remotes/origin/master')

		self.assertRaises(NotImplementedError, subject.prepare)

	def test_load_call_graph(self):
		subject = Subject('subject', 'https://github.com')

		self.assertRaises(errors.SubjectNotPreparedError, 
			subject.load_call_graph)

	def test_get_absolute_path(self):
		subject = Subject('subject', 'https://github.com')

		self.assertEqual(os.path.join(subject.__source_dir__, 'main.c'),
			subject.get_absolute_path('main.c'))

		self.assertEqual(os.path.join(subject.__source_dir__, 'main'),
			subject.get_absolute_path('main'))

	def test_load_function_sloc(self):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		sloc_folder_url = (
			'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.'
			'googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2h'
			'Qal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/FFmpeg/SLOC/'
		)
		subject = Subject(name, clone_url, sloc_folder_url=sloc_folder_url)
		subject.initialize()
		subject.load_function_sloc()

		self.assertIsNotNone(subject.function_sloc)

		shutil.rmtree(subject.scratch_dir)

	def test_get_function_sloc(self):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		sloc_folder_url = (
			'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.'
			'googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2h'
			'Qal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/FFmpeg/SLOC/'
		)
		git_reference = 'refs/remotes/origin/release/0.6'
		subject = Subject(name, clone_url, git_reference=git_reference, 
			sloc_folder_url=sloc_folder_url)
		subject.initialize()
		subject.load_function_sloc()

		self.assertEqual(
			45, 
			subject.get_function_sloc('start_children', 'ffserver.c')
		)

		self.assertEqual(
			53, 
			subject.get_function_sloc('av_exit', 'ffmpeg.c')
		)
		# TODO: Uncomment after /attack-surface-metrics/issues/39 is
		# 	resolved
		# self.assertEqual(
		# 	6, 
		# 	subject.get_function_sloc('bswap_32', 'bswap.h')
		# )

		shutil.rmtree(subject.scratch_dir)

	def test_load_vulnerable_functions(self):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		git_reference = 'refs/remotes/origin/release/2.2'
		subject = Subject(name, clone_url, git_reference=git_reference)

		commit_hashes = [
			'd7470271c7ca3f412aac6b29fb4b8f22ad5c0238',
			'a06432b6c315fda5a9cc69059fd106d231e7da6c',
			'5d6f8bab02ba6d8434188172b31a4e1ac0a00756',
			'4fde30ba9d050443fb14116fb206d0d37092bed0',
			'b0964918d882dd3ae589f76df01551ca0234d910',
			'43881c773277c90ccb0dbfd2d5c3afd8f8603597',
			'42bdcebf3360fca957e8224ff0a6573b05dbc249',
			'64be1a45eb2604deca259319780ce02bd921859b',
			'f8bd98ae4d691fa7405856d83ca3d304429cc6f0',
			'f2c6e2c3b4ee0b0b8e202ef2d8a6f3780d20595f',
			'e5ccd894d1c1c07c39876b650b2993de16547fb0',
			'6287107eae40750f47ec3888c52fd94a9c697b38',
			'0397d434054ab9a80fbf8e2357538ca29d4fe427',
			'1ad1723c24cd2683df6d00a83b6f28d3ff45fb96',
			'842b6c14bcfc1c5da1a2d288fd65386eb8c158ad',
			'c919e1ca2ecfc47d796382973ba0e48b8f6f92a2',
			'ec9578d54d09b64bf112c2bf7a34b1ef3b93dbd3',
			'f58eab151214d2d35ff0973f2b3e51c5eb372da4',
			'7d9c059a3525aa9f3e257b4c13df2b8c30409f3c'
		]

		subject.initialize()
		subject.load_vulnerable_functions(commit_hashes)

		self.assertIsNotNone(subject.vulnerable_functions)

		shutil.rmtree(subject.scratch_dir)

	def test_is_function_vulnerable(self):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		git_reference = 'refs/remotes/origin/release/2.2'
		subject = Subject(name, clone_url, git_reference=git_reference)

		commit_hashes = [
			'd7470271c7ca3f412aac6b29fb4b8f22ad5c0238',
			'a06432b6c315fda5a9cc69059fd106d231e7da6c',
			'5d6f8bab02ba6d8434188172b31a4e1ac0a00756',
			'4fde30ba9d050443fb14116fb206d0d37092bed0',
			'b0964918d882dd3ae589f76df01551ca0234d910',
			'43881c773277c90ccb0dbfd2d5c3afd8f8603597',
			'42bdcebf3360fca957e8224ff0a6573b05dbc249',
			'64be1a45eb2604deca259319780ce02bd921859b',
			'f8bd98ae4d691fa7405856d83ca3d304429cc6f0',
			'f2c6e2c3b4ee0b0b8e202ef2d8a6f3780d20595f',
			'e5ccd894d1c1c07c39876b650b2993de16547fb0',
			'6287107eae40750f47ec3888c52fd94a9c697b38',
			'0397d434054ab9a80fbf8e2357538ca29d4fe427',
			'1ad1723c24cd2683df6d00a83b6f28d3ff45fb96',
			'842b6c14bcfc1c5da1a2d288fd65386eb8c158ad',
			'c919e1ca2ecfc47d796382973ba0e48b8f6f92a2',
			'ec9578d54d09b64bf112c2bf7a34b1ef3b93dbd3',
			'f58eab151214d2d35ff0973f2b3e51c5eb372da4',
			'7d9c059a3525aa9f3e257b4c13df2b8c30409f3c'
		]

		subject.initialize()
		subject.load_vulnerable_functions(commit_hashes)

		self.assertTrue(subject.is_function_vulnerable(
			'mjpeg_decode_app', './libavcodec/mjpegdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'ff_mjpeg_decode_dht', './libavcodec/mjpegdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'ff_mjpeg_decode_sof', './libavcodec/mjpegdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'decode_frame', './libavcodec/pngdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'raw_init_decoder', './libavcodec/rawdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'ff_hevc_decode_nal_sps', './libavcodec/hevc_ps.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'avcodec_align_dimensions2', './libavcodec/utils.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'mm_decode_intra', './libavcodec/mmvideo.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'tiff_decode_tag', './libavcodec/tiff.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'cinepak_decode_vectors', './libavcodec/cinepak.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'gif_read_image', './libavcodec/gifdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'decode_frame', './libavcodec/iff.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'encode_slice', './libavcodec/proresenc_kostya.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'encode_frame', './libavcodec/proresenc_kostya.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'get_len', './libavutil/lzo.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'mpegts_write_pat', './libavformat/mpegtsenc.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'mpegts_write_pmt', './libavformat/mpegtsenc.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'msrle_decode_frame', './libavcodec/msrle.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'tak_decode_frame', './libavcodec/takdec.c'
		))

		self.assertFalse(subject.is_function_vulnerable(
			'', './libavcodec/wmalosslessdec.c'
		))
		self.assertFalse(subject.is_function_vulnerable(
			'', './libavcodec/smc.c'
		))

		shutil.rmtree(subject.scratch_dir)

		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		git_reference = 'refs/tags/n2.2.9'
		subject = Subject(name, clone_url, git_reference=git_reference)
		
		commit_hashes = [
			'6287107eae40750f47ec3888c52fd94a9c697b38',
			'e5ccd894d1c1c07c39876b650b2993de16547fb0',
			'f2c6e2c3b4ee0b0b8e202ef2d8a6f3780d20595f',
			'f8bd98ae4d691fa7405856d83ca3d304429cc6f0',
			'64be1a45eb2604deca259319780ce02bd921859b',
			'42bdcebf3360fca957e8224ff0a6573b05dbc249',
			'43881c773277c90ccb0dbfd2d5c3afd8f8603597',
			'b0964918d882dd3ae589f76df01551ca0234d910'
		]

		subject.initialize()
		subject.load_vulnerable_functions(commit_hashes)

		self.assertTrue(subject.is_function_vulnerable(
			'gif_read_image', './libavcodec/gifdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'cinepak_decode_vectors', './libavcodec/cinepak.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'mm_decode_intra', './libavcodec/mmvideo.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'avcodec_align_dimensions2', './libavcodec/utils.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'decode_frame', './libavcodec/pngdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'ff_mjpeg_decode_dht', './libavcodec/mjpegdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'ff_mjpeg_decode_sof', './libavcodec/mjpegdec.c'
		))
		self.assertTrue(subject.is_function_vulnerable(
			'tiff_decode_tag', './libavcodec/tiff.c'
		))

		self.assertFalse(subject.is_function_vulnerable(
			'', './libavcodec/smc.c'
		))

		shutil.rmtree(subject.scratch_dir)

	def test_cflow_file_path(self):
		subject = Subject('subject', 'https://github.com')

		self.assertEqual(
			os.path.join(
				subject.scratch_dir, md5(b'subject').hexdigest(), 'cflow.txt'
			),
			subject.cflow_file_path
		)

	def test_gprof_file_path(self):
		subject = Subject('subject', 'https://github.com')

		self.assertEqual(
			os.path.join(
				subject.scratch_dir, md5(b'subject').hexdigest(), 'gprof.txt'
			),
			subject.gprof_file_path
		)

	def test_execute(self):
		subject = Subject('subject', 'https://github.com')

		return_code = subject.__execute__(['echo', 'nocturnal'], 
			cwd='/')
		self.assertEqual(0, return_code)
		
		return_code = subject.__execute__(['exit 2'], 
			cwd='/')
		self.assertEqual(2, return_code)

	def test_clean_up(self):
		subject = Subject('subject', 'https://github.com')

		self.assertRaises(NotImplementedError, subject.__clean_up__)

	def test_download_sloc_file(self):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		sloc_folder_url = (
			'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.'
			'googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2h'
			'Qal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/FFmpeg/SLOC/'
		)
		subject = Subject(name, clone_url, sloc_folder_url=sloc_folder_url)

		subject.__download_sloc_file__()
		self.assertTrue(os.path.exists(subject.__sloc_file_path__))

	def test_source_dir(self):
		subject = Subject('subject', 'https://github.com')

		self.assertEqual(
			os.path.join(
				subject.scratch_dir, md5(b'subject').hexdigest(), 'src'
			),
			subject.__source_dir__
		)

	def test_sloc_file_url(self):
		subject = Subject('subject', 'https://github.com', 
			sloc_folder_url='https://google.com/helloworld/SLOC/')

		self.assertEqual(
			'https://google.com/helloworld/SLOC/subject.csv',
			subject.__sloc_file_url__
		)

		subject = Subject('subject', 'https://github.com', 
			git_reference='refs/remotes/origin/release/2.5',
			sloc_folder_url='https://google.com/helloworld/SLOC/')

		self.assertEqual(
			'https://google.com/helloworld/SLOC/2.5.0.subject.csv',
			subject.__sloc_file_url__
		)

	def test_sloc_file_path(self):
		subject = Subject('subject', 'https://github.com')

		self.assertEqual(
			os.path.join(
				subject.scratch_dir, md5(b'subject').hexdigest(), 'sloc.csv'
			),
			subject.__sloc_file_path__
		)

	def test_cflow_file_exists(self):
		subject = Subject('subject', 'https://github.com')

		self.assertFalse(subject.__cflow_file_exists__)
		
		if not os.path.exists(subject.__source_dir__):
			os.makedirs(subject.__source_dir__)

		file_ = open(subject.cflow_file_path, 'w')
		file_.close()

		self.assertTrue(subject.__cflow_file_exists__)

		os.remove(subject.cflow_file_path)

	def test_gprof_file_exists(self):
		subject = Subject('subject', 'https://github.com')

		self.assertFalse(subject.__gprof_file_exists__)
		
		if not os.path.exists(subject.__source_dir__):
			os.makedirs(subject.__source_dir__)

		file_ = open(subject.gprof_file_path, 'w')
		file_.close()

		self.assertTrue(subject.__gprof_file_exists__)

		os.remove(subject.gprof_file_path)

	def test_clone_exists(self):
		subject = Subject('backbone', 
			'https://github.com/jashkenas/backbone.git',)

		subject.clone()
		self.assertTrue(subject.__clone_exists__)

		shutil.rmtree(subject.scratch_dir)

	def tearDown(self):
		pass
