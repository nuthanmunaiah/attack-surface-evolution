import subprocess

from app.subjects import subject


class FFmpeg(subject.Subject):
    def __init__(self, num_jobs=1, git_reference=None, scratch_root='/tmp'):
        name = 'FFmpeg'
        clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
        sloc_folder_url = (
            'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.'
            'googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2h'
            'Qal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/FFmpeg/SLOC/'
        )

        super().__init__(
            name, clone_url, git_reference, sloc_folder_url, scratch_root
        )

        self.num_jobs = num_jobs

    def configure(self):
        cmd = (
            './configure --samples=fate-suite/ --extra-cflags=\'-g -pg\''
            ' --extra-ldflags=\'-g -pg\''
        )
        return self.__execute__(cmd)

    def test(self):
        cmd = 'make -j %d fate-rsync' % self.num_jobs
        returncode = self.__execute__(cmd)

        returncode = 0
        if returncode == 0:
            cmd = 'make -j %d fate' % self.num_jobs
            returncode = self.__execute__(cmd)

        return returncode

    def cflow(self):
        cmd = (
            'cflow -b -r '
            '`find -name "*.c" -or -name "*.h" | grep -vwE "(tests|doc)"`'
        )

        with open(self.cflow_file_path, 'w+') as _cflow_file:
            return self.__execute__(cmd, stdout=_cflow_file)

    def gprof(self):
        cmd = 'gprof -q -b -l -c -z -L ffmpeg_g'

        with open(self.gprof_file_path, 'w+') as _gprof_file:
            returncode = self.__execute__(cmd, stdout=_gprof_file)

        # gprof's -L is printing absolute path instead of relative path.
        #   Fixing the paths used sed.
        # Examples:
        #   /home/rady/ffmpeg/libavcodec/utils.c     > ./libavcodec/utils.c
        #   /home/rady/ffmpeg/./libavutil/internal.h > ./libavutil/internal.h

        self.__execute__(
            "sed -i 's;{0}\/\.;.;g' {1}".format(
                self.__source_dir__.replace('/', '\/'),
                self.gprof_file_path
            )
        )
        self.__execute__(
            "sed -i 's;{0};.;g' {1}".format(
                self.__source_dir__.replace('/', '\/'),
                self.gprof_file_path
            )
        )

        return returncode
