import os
import subprocess

from app.subjects import subject


class cURL(subject.Subject):
    def __init__(self, name, remote, scratch_root):
        super().__init__(name, remote, scratch_root)

    def configure(self, options):
        self.debug('Configuring {0}'.format(self.name))

        returncode = self.execute('./buildconf')
        if returncode == 0:
            returncode = self.execute('./configure {0}'.format(options))
        return returncode

    def make(self, processes=1):
        self.debug('Building {0}'.format(self.name))
        cmd = 'make -j %d' % processes
        return self.execute(cmd)

    def test(self, processes=1):
        self.debug('Testing {0}'.format(self.name))
        cmd = 'make -j %d -C tests' % processes
        self.execute(cmd)

        # Returning non-zero return value to allow execution of manual script
        return 2

    def __gprof__(self, gmon_path, gprof_path):
        self.debug(
            'Generating call graph for {0} using gprof with profile '
            'information from {1}'.format(self.name, gmon_path)
        )
        if 'basegmon.out' in gmon_path:
            cmd = 'gprof -q -b -l -c -z -L src/.libs/curl {0}'
        else:
            cmd = 'gprof -q -b -l -c -L src/.libs/curl {0}'

        cmd = cmd.format(gmon_path, gprof_path)

        with open(gprof_path, 'w+') as _gprof_file:
            returncode = self.execute(cmd, stdout=_gprof_file)

        # gprof's -L is printing absolute path instead of relative path.
        #   Fixing the paths using sed.
        # Examples:
        #   /home/rady/curl/src/src/../lib/rawstr.c > ./lib/help.c
        #   /home/rady/curl/src/src/lib/rawstr.c > ./lib/help.c
        #   /home/rady/curl/src/lib/utils.c     > ./lib/utils.c

        self.execute(
            "sed -i 's;{0}\/src\/\.\.;.;g' {1}".format(
                self.source_dir.replace('/', '\/'), gprof_path
            )
        )
        self.execute(
            "sed -i 's;{0}\/src;.;g' {1}".format(
                self.source_dir.replace('/', '\/'), gprof_path
            )
        )
        self.execute(
            "sed -i 's;{0};.;g' {1}".format(
                self.source_dir.replace('/', '\/'), gprof_path
            )
        )

        return returncode
