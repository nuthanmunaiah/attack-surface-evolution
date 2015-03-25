import os
import subprocess
from django.test import TestCase
from hashlib import md5

from app.subjects import SubjectNotPreparedError
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
		uuid = md5(b'subject').hexdigest()
		self.assertEqual(uuid, subject.uuid)
		self.assertEqual(False, subject.prepared)

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

		self.assertRaises(NotImplementedError, subject.configure)
		self.assertRaises(NotImplementedError, subject.test)
		self.assertRaises(NotImplementedError, subject.cflow)
		self.assertRaises(NotImplementedError, subject.gprof)
		self.assertRaises(NotImplementedError, subject.__clean_up__)

		self.assertRaises(SubjectNotPreparedError, subject.get_call_graph)

		(out, err) = subject.__execute__(['echo', 'nocturnal'], 
			cwd='/', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.assertEqual('nocturnal\n', out.decode())
		self.assertEqual('', err.decode())

		(out, err) = subject.__execute__(['ls', 'nocturnal'], 
			cwd='/', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.assertEqual('', out.decode())
		self.assertEqual('ls: cannot access nocturnal: No such file or' 
			' directory\n', err.decode())

	def tearDown(self):
		pass
