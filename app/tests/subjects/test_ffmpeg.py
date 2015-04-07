import os
import subprocess
from django.test import TestCase
from hashlib import md5

from app.subjects.subject import Subject
from app.subjects.ffmpeg import FFmpeg
from attacksurfacemeter.call_graph import CallGraph


class FFmpegTestCase(TestCase):
	def setUp(self):
		self.ffmpeg = FFmpeg(num_jobs=2)

		self.ffmpeg.initialize_source()

	def test_ffmpeg(self):
		self.assertEqual('FFmpeg', self.ffmpeg.name)
		self.assertEqual('https://github.com/FFmpeg/FFmpeg.git', 
			self.ffmpeg.clone_url)
		self.assertEqual(2, self.ffmpeg.num_jobs)
		self.assertIsInstance(self.ffmpeg, FFmpeg)
		self.assertIsInstance(self.ffmpeg, Subject)

	def test_prepare(self):
		self.ffmpeg.prepare()

		# Test: Subject.configure()
		self.assertTrue(os.path.exists(
			os.path.join(self.ffmpeg.__source_dir__, 'config.log')
		))

		# Test: Subject.test()
		self.assertTrue(
			os.path.exists(
				os.path.join(self.ffmpeg.__source_dir__, 'ffmpeg_g')
			)
		)
		self.assertTrue(
			os.path.exists(
				os.path.join(self.ffmpeg.__source_dir__, 'gmon.out')
			)
		)

		# Test: Subject.cflow()
		self.assertTrue(
			os.path.exists(self.ffmpeg.cflow_file_path)
		)

		# Test: Subject.gprof()
		self.assertTrue(
			os.path.exists(self.ffmpeg.gprof_file_path)
		)

		# Test: Subject.get_call_graph()
		call_graph = self.ffmpeg.get_call_graph()
		self.assertIsInstance(call_graph, CallGraph)

		self.assertTrue(self.ffmpeg.prepared)

	def tearDown(self):
		pass
