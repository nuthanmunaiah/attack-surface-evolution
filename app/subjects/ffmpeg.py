import subprocess

from app.subjects import subject


class FFmpeg(subject.Subject):
	def __init__(self, num_cores, git_reference=None, scratch_root='/tmp'):
		name = 'FFmpeg'
		clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
		super().__init__(name, clone_url, git_reference, scratch_root)

		# TODO: Consider removing
		self.num_cores = num_cores

	def configure(self):
		cmd = ('./configure --samples=fate-suite/ --extra-cflags=\'-pg\''
			' --extra-ldflags=\'-pg\'')
		self.__execute__(cmd, stdout=subprocess.DEVNULL)

	def test(self):
		cmd = 'make -j %d fate-rsync' % self.num_cores
		self.__execute__(cmd, stdout=subprocess.DEVNULL)

		cmd = 'make  -j %d fate' % self.num_cores
		self.__execute__(cmd, stdout=subprocess.DEVNULL)

	def cflow(self):
		cmd = ('cflow -b -r '
			'`find -name "*.c" -or -name "*.h" | grep -vwE "(tests|doc)"`')

		with open(self.cflow_file_path, 'w+') as _cflow_file:
			self.__execute__(cmd, stdout=_cflow_file)

	def gprof(self):
		cmd = 'gprof -q -b -l -c -z ffmpeg_g'

		with open(self.gprof_file_path, 'w+') as _gprof_file:
			self.__execute__(cmd, stdout=_gprof_file)
