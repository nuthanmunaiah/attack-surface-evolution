import os
import subprocess

from app.subjects import subject


class FFmpeg(subject.Subject):
    def __init__(self, name, remote, scratch_root):
        super().__init__(name, remote, scratch_root)

    def configure(self, options):
        self.debug('Configuring {0}'.format(self.name))
        cmd = './configure {0}'.format(options)
        return self.execute(cmd)

    def make(self, processes=1):
        self.debug('Building {0}'.format(self.name))
        cmd = 'make -j %d' % processes
        return self.execute(cmd)

    def test(self, processes):
        self.debug('Testing {0}'.format(self.name))
        cmd = 'make -j %d fate-rsync' % processes
        self.execute(cmd)

        # Returning non-zero return value to allow execution of manual script
        return 2

    def __gprof__(self, gmon_path, gprof_path):
        self.debug(
            'Generating call graph for {0} using gprof with profile '
            'information from {1}'.format(self.name, gmon_path)
        )
        cmd = 'gprof -q -b -l -c -L ffmpeg_g {0}'
        cmd = cmd.format(gmon_path)

        with open(gprof_path, 'w+') as _gprof_file:
            returncode = self.execute(cmd, stdout=_gprof_file)

        # gprof's -L is printing absolute path instead of relative path.
        #   Fixing the paths using sed.
        # Examples:
        #   /home/rady/ffmpeg/./libavutil/internal.h > ./libavutil/internal.h
        #   /home/rady/ffmpeg//libavfilter/common.h  > ./libavfilter/common.h
        #   /home/rady/ffmpeg/libavcodec/utils.c     > ./libavcodec/utils.c

        self.execute(
            "sed -i 's;{0}\/\.;.;g' {1}".format(
                self.source_dir.replace('/', '\/'), gprof_path
            )
        )
        self.execute(
            "sed -i 's;{0}\/\/;./;g' {1}".format(
                self.source_dir.replace('/', '\/'), gprof_path
            )
        )
        self.execute(
            "sed -i 's;{0};.;g' {1}".format(
                self.source_dir.replace('/', '\/'), gprof_path
            )
        )

        return returncode
