import os
import subprocess
from django.test import TestCase
from hashlib import md5

from app.subjects import SubjectNotPreparedError
from app.subjects.subject import Subject
from app.subjects.ffmpeg import FFmpeg
from attacksurfacemeter.call_graph import CallGraph


class SubjectTestCase(TestCase):
	def setUp(self):
		pass

	def test_ffmpeg(self):
		ffmpeg = FFmpeg(num_cores=4)

		self.assertEqual(4, ffmpeg.num_cores)
		self.assertIsInstance(ffmpeg, FFmpeg)
		self.assertIsInstance(ffmpeg, Subject)

		ffmpeg.prepare()
		
		# Test: Was clone successful?
		self.assertTrue(
			os.path.exists(os.path.join(ffmpeg.__source_dir__, '.git'))
		)

		# Test: Was checkout successful?
		process = subprocess.Popen(
			['git','branch'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
			cwd=ffmpeg.__source_dir__)
		(out, err) = process.communicate()

		self.assertEqual('* master\n', out.decode())
		
		# Test: Was build successful?
		self.assertTrue(
			os.path.exists(os.path.join(ffmpeg.__source_dir__, 'ffmpeg_g'))
		)

		# Test: Was test successful?
		self.assertTrue(
			os.path.exists(os.path.join(ffmpeg.__source_dir__, 'gmon.out'))
		)

		# Test: Was cflow successful?
		self.assertTrue(
			os.path.exists(ffmpeg.cflow_file_path)
		)
		
		# Test: Was gprof successful?
		self.assertTrue(
			os.path.exists(ffmpeg.gprof_file_path)
		)

		self.assertTrue(ffmpeg.prepared)

		call_graph = ffmpeg.get_call_graph()
		self.assertIsInstance(call_graph, CallGraph)

	def tearDown(self):
		pass
