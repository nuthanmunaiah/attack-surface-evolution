import csv
import os
import re
import subprocess
import threading
import hashlib
from urllib import parse

import requests
from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from app import errors, helpers
from app.gitapi import Repo


class Subject(object):
	def __init__(self, name, clone_url, git_reference=None, 
		sloc_folder_url=None, scratch_root='/tmp'):

		self.name = name
		self.clone_url = clone_url
		self.git_reference = git_reference
		self.sloc_folder_url = sloc_folder_url
		self.repo = None
		self.scratch_dir = os.path.join(scratch_root, name)

		md5 = hashlib.md5()
		md5.update(name.encode())
		if git_reference:
			md5.update(git_reference.encode())
		self.uuid = md5.hexdigest()

		self.prepared = False
		self.initialized = False

		self.call_graph = None
		self.function_sloc = None
		self.vulnerable_functions = None

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

	def initialize(self):
		if not self.initialized:
			self.clone()
			self.checkout()
			self.__download_sloc_file__()

			self.initialized = True

	def prepare(self):
		if not (self.__cflow_file_exists__ and self.__gprof_file_exists__):
			self.initialize()
			self.configure()
			self.test()

			# cflow and gprof are independent of one another, so run them in 
			# 	parallel
			cflow_thread = threading.Thread(target=self.cflow, 
				name='subject.cflow')
			gprof_thread = threading.Thread(target=self.gprof, 
				name='subject.gprof')

			cflow_thread.start()
			gprof_thread.start()

			cflow_thread.join()
			gprof_thread.join()

		self.prepared = True

	def load_call_graph(self):
		if not self.prepared:
			raise errors.SubjectNotPreparedError(
				'prepare() must be invoked before load_call_graph()'
			)

		if not self.call_graph:
			cflow_loader = CflowLoader(self.cflow_file_path, reverse=True)
			gprof_loader = GprofLoader(self.gprof_file_path, reverse=False)

			self.call_graph = CallGraph.from_merge(
				CallGraph.from_loader(cflow_loader), 
				CallGraph.from_loader(gprof_loader)
			)
			self.call_graph.remove_standard_library_calls()

	def get_absolute_path(self, name):
		return os.path.join(self.__source_dir__, name)

	def load_function_sloc(self):
		if not self.function_sloc:
			re_function = re.compile('^([^\(]*)')
			
			self.function_sloc = dict()
			with open(self.__sloc_file_path__, 'r') as _sloc_file:
				reader = csv.reader(_sloc_file)
				next(reader)  # Skipping the header
				for row in reader:
					func = re_function.match(row[1]).group(1)
					file_ = row[0]
					self.function_sloc['%s@%s' % (func, file_)] = int(row[3])

	def get_function_sloc(self, name, in_file):
		key = '%s@%s' % (name, in_file)
		if key in self.function_sloc:
			return self.function_sloc[key]

	def load_vulnerable_functions(self, commit_hashes):
		if not self.vulnerable_functions and commit_hashes:
			self.vulnerable_functions = dict()
			for commit_hash in commit_hashes:
				for file_ in self.repo.get_files_changed(commit_hash):
					file_path = self.get_absolute_path(file_)
					file_path = file_path.replace(self.__source_dir__, '.')
					
					if file_path not in self.vulnerable_functions:
						self.vulnerable_functions[file_path] = set()

					for function in self.repo.get_functions_changed(
						commit_hash, file=file_):

						self.vulnerable_functions[file_path].add(function)

	def is_function_vulnerable(self, name, in_file):
		if in_file in self.vulnerable_functions:
			return name in self.vulnerable_functions[in_file]
		return False

	@property
	def cflow_file_path(self):
		return os.path.join(self.scratch_dir, self.uuid, 'cflow.txt')

	@property
	def gprof_file_path(self):
		return os.path.join(self.scratch_dir, self.uuid, 'gprof.txt')

	def __execute__(self, command, cwd=None, stdout=subprocess.DEVNULL, 
		stderr=subprocess.DEVNULL):

		if not cwd:
			cwd = self.__source_dir__

		process = subprocess.Popen(command, stdout=stdout, 
			stderr=stderr, cwd=cwd, shell=True)

		return process.wait()

	def __clean_up__(self):
		raise NotImplementedError

	def __download_sloc_file__(self):
		if (self.__sloc_file_url__ and not self.__sloc_file_exists__):
			with open(self.__sloc_file_path__, 'w+') as file_:
				response = requests.get(self.__sloc_file_url__, stream=True)
				for chunk in response.iter_content(1024, True):
					file_.write(chunk)
					file_.flush()

	@property
	def __source_dir__(self):
		return os.path.join(self.scratch_dir, self.uuid, 'src')

	@property
	def __sloc_file_url__(self):
		url = None

		if self.sloc_folder_url:
			sloc_file_name = '{0}.csv'.format(self.name)
			
			if self.git_reference:
				sloc_file_name = '{0}.{1}'.format(
					'%d.%d.%d' % helpers.get_version_components(
						self.git_reference
					),
					sloc_file_name
				)

			url = parse.urljoin(self.sloc_folder_url, sloc_file_name)

		return url

	@property
	def __sloc_file_path__(self):
		return os.path.join(self.scratch_dir, self.uuid, 'sloc.csv')

	@property
	def __sloc_file_exists__(self):
	    return os.path.exists(self.__sloc_file_path__)

	@property
	def __cflow_file_exists__(self):
		return os.path.exists(self.cflow_file_path)

	@property
	def __gprof_file_exists__(self):
		return os.path.exists(self.gprof_file_path)

	@property
	def __clone_exists__(self):
		return os.path.exists(self.__source_dir__)
