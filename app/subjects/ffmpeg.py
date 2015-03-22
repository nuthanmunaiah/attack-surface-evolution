import subprocess

from app.subjects import subject


class FFmpeg(subject.Subject):
	def __init__(self, num_cores, git_reference=None, scratch_root='/tmp'):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		super().__init__(name, clone_url, git_reference, scratch_root)

		self.num_cores = num_cores

	def build(self):
		cmd = './configure --extra-cflags=\'-pg\' --extra-ldflags=\'-pg\''
		self.__execute__(cmd)

		cmd = 'make -j %d' % self.num_cores
		self.__execute__(cmd)

	def test(self):
		cmd = 'make -j %d fate-rsync SAMPLES=fate-suite/' % self.num_cores
		self.__execute__(cmd)

		cmd = 'make -j %d fate SAMPLES=fate-suite/' % self.num_cores
		self.__execute__(cmd)

	def cflow(self):
		cmd = ('cflow -br '
			'`find -name "*.c" -or -name "*.h" | grep -vwE "(tests|doc)"`')

		with open(self.cflow_file_path, 'w+') as cflow_file:
			self.__execute__(cmd, stdout=cflow_file)

	def gprof(self):
		cmd = 'gprof -qblcz ffmpeg_g'

		with open(self.gprof_file_path, 'w+') as gprof_file:
			self.__execute__(cmd, stdout=gprof_file)
