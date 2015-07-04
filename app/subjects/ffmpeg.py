import os
import subprocess

from app.subjects import subject


class FFmpeg(subject.Subject):
    def __init__(
            self, configure_options, processes=1, git_reference=None,
            scratch_root='~'
    ):

        name = 'FFmpeg'
        clone_url = 'https://github.com/FFmpeg/FFmpeg.git'
        remote_url = (
            'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.'
            'googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2h'
            'Qal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/FFmpeg/'
        )

        if '~' in scratch_root:
            scratch_root = os.path.expanduser(scratch_root)

        super().__init__(
            name, clone_url, configure_options, processes, git_reference,
            remote_url, scratch_root
        )

    def configure(self):
        cmd = './configure {0}'.format(self.configure_options)
        return self.execute(cmd)

    def make(self):
        cmd = 'make -j %d' % self.processes
        return self.execute(cmd)

    def test(self):
        cmd = 'make -j %d fate-rsync' % self.processes
        self.execute(cmd)

        # Returning non-zero return value to allow execution of manual script
        return 2

    def cflow(self):
        cmd = (
            'cflow -b -r '
            '`find -name "*.c" -or -name "*.h" | grep -vwE "(tests|doc)"`'
        )

        with open(self.cflow_file_path, 'w+') as _cflow_file:
            return self.execute(cmd, stdout=_cflow_file)

    def gprof(self, index=None):
        if index is not None:
            gmon_file_path = os.path.join(
                self.gmon_files_dir, self.gmon_files_name[index])
            gprof_file_path = os.path.join(
                self.gprof_files_dir,
                '{0}.txt'.format(self.gmon_files_name[index])
            )
            return self.__gprof__(gmon_file_path, gprof_file_path)

        returncode = 0
        for gmon_file in self.gmon_files_name:
            gmon_file_path = os.path.join(self.gmon_files_dir, gmon_file)
            gprof_file_path = os.path.join(
                self.gprof_files_dir, '{0}.txt'.format(gmon_file)
            )
            returncode = self.__gprof__(gmon_file_path, gprof_file_path)

        return returncode

    def __gprof__(self, gmon_file_path, gprof_file_path):
        if 'basegmon.out' in gmon_file_path:
            cmd = 'gprof -q -b -l -c -z -L ffmpeg_g {0}'
        else:
            cmd = 'gprof -q -b -l -c -L ffmpeg_g {0}'

        cmd = cmd.format(gmon_file_path, gprof_file_path)

        with open(gprof_file_path, 'w+') as _gprof_file:
            returncode = self.execute(cmd, stdout=_gprof_file)

        # gprof's -L is printing absolute path instead of relative path.
        #   Fixing the paths using sed.
        # Examples:
        #   /home/rady/ffmpeg/./libavutil/internal.h > ./libavutil/internal.h
        #   /home/rady/ffmpeg//libavfilter/common.h  > ./libavfilter/common.h
        #   /home/rady/ffmpeg/libavcodec/utils.c     > ./libavcodec/utils.c

        self.execute(
            "sed -i 's;{0}\/\.;.;g' {1}".format(
                self.source_dir.replace('/', '\/'),
                gprof_file_path
            )
        )
        self.execute(
            "sed -i 's;{0}\/\/;./;g' {1}".format(
                self.source_dir.replace('/', '\/'),
                gprof_file_path
            )
        )
        self.execute(
            "sed -i 's;{0};.;g' {1}".format(
                self.source_dir.replace('/', '\/'),
                gprof_file_path
            )
        )

        return returncode
