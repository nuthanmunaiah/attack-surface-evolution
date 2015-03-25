import os
import subprocess
import threading
import hashlib

from attacksurfacemeter.call_graph import CallGraph
from loaders.cflow_loader import CflowLoader
from loaders.gprof_loader import GprofLoader
from app.gitapi import Repo
from app.subjects import SubjectNotPreparedError

class Subject(object):
	def __init__(self, name, clone_url, git_reference=None, scratch_root='/tmp'):
		self.name = name
		self.clone_url = clone_url
		self.git_reference = git_reference
		self.repo = None
		self.scratch_dir = os.path.join(scratch_root, name)

		md5 = hashlib.md5()
		md5.update(name.encode())
		if git_reference:
			md5.update(git_reference.encode())
		self.uuid = md5.hexdigest()

		self.prepared = False

	def clone(self):
		if not self.__clone_exists__:
			self.repo = Repo.git_clone(self.clone_url, self.__source_dir__)
		else:
			self.repo = Repo(self.__source_dir__)

	def checkout(self):
		if self.git_reference:
			self.repo.git_checkout(self.git_reference)

	def configure(self):
		raise NotImplementedError

	def test(self):
		raise NotImplementedError

	def cflow(self):
		raise NotImplementedError

	def gprof(self):
		raise NotImplementedError

	def prepare(self):
		if not (self.__cflow_file_exists__ and self.__gprof_file_exists__):
			self.clone()
			self.checkout()
			self.configure()
			self.test()

			# cflow and gprof are independent of one another, so run them in 
			# parallel
			cflow_thread = threading.Thread(target=self.cflow, 
				name='subject.cflow')
			gprof_thread = threading.Thread(target=self.gprof, 
				name='subject.gprof')

			cflow_thread.start()
			gprof_thread.start()

			cflow_thread.join()
			gprof_thread.join()

		self.prepared = True

	def get_call_graph(self):
		if not self.prepared:
			raise SubjectNotPreparedError(
				'prepare() must be invoked before get_call_graph()'
			)

		cflow_loader = CflowLoader(self.cflow_file_path, reverse=True)
		gprof_loader = GprofLoader(self.gprof_file_path, reverse=False)

		call_graph = CallGraph.from_merge(
			CallGraph.from_loader(cflow_loader), 
			CallGraph.from_loader(gprof_loader)
		)
		call_graph.remove_standard_library_calls()

		return call_graph

	def get_file_path(self, name):
		return os.path.join(self.__source_dir__, name)

	@property
	def cflow_file_path(self):
		return os.path.join(self.scratch_dir, self.uuid, 'cflow.txt')

	@property
	def gprof_file_path(self):
		return os.path.join(self.scratch_dir, self.uuid, 'gprof.txt')

	@property
	def __source_dir__(self):
		return os.path.join(self.scratch_dir, self.uuid, 'src')

	@property
	def __cflow_file_exists__(self):
		return os.path.exists(self.cflow_file_path)

	@property
	def __gprof_file_exists__(self):
		return os.path.exists(self.gprof_file_path)

	@property
	def __clone_exists__(self):
		return os.path.exists(self.__source_dir__)

	def __execute__(self, command, cwd=None, stdout=None, 
		stderr=subprocess.DEVNULL):
		
		# TODO: Remove
		print(command)

		if not cwd:
			cwd = self.__source_dir__

		process = subprocess.Popen(command, stdout=stdout, stderr=stderr, 
			cwd=cwd, shell=True)

		return process.wait()

	def __clean_up__(self):
		raise NotImplementedError
