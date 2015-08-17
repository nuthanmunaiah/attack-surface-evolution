import os
import subprocess

from app.subjects import subject


class Wireshark(subject.Subject):
    def __init__(
            self, configure_options, processes=1, git_reference=None,
            scratch_root='~'
    ):

        name = 'Wireshark'
        clone_url = 'https://github.com/wireshark/wireshark.git'
        remote_url = (
            'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.'
            'googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2h'
            'Qal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/Wireshark/'
        )

        if '~' in scratch_root:
            scratch_root = os.path.expanduser(scratch_root)

        super().__init__(
            name, clone_url, configure_options, processes, git_reference,
            remote_url, scratch_root
        )

    def configure(self):
        self.__dbug__('Configuring {0}'.format(self.name))

        cmd = './autogen.sh'
        returncode = self.execute(cmd)
        if returncode == 0:
            cmd = './configure {0}'.format(self.configure_options)
            returncode = self.execute(cmd)
        return returncode

    def make(self):
        self.__dbug__('Building {0}'.format(self.name))
        cmd = 'make -j %d' % self.processes
        return self.execute(cmd)

    def test(self):
        # Returning non-zero return value to allow execution of manual script
        return 2

    def __gprof__(self, gmon_file_path, gprof_file_path):
        self.__dbug__(
            'Generating call graph for {0} using gprof with profile '
            'information from {1}'.format(self.name, gmon_file_path)
        )
        cmd = 'gprof -q -b -l -c -L .libs/wireshark {0}'
        cmd = cmd.format(gmon_file_path)

        with open(gprof_file_path, 'w+') as _gprof_file:
            returncode = self.execute(cmd, stdout=_gprof_file)

        # gprof's -L is printing absolute path instead of relative path.
        #   Fixing the paths using sed.
        # Examples:
        #   /home/rady/wireshark/wireshark.c     > ./wireshark.c

        self.execute(
            "sed -i 's;{0};.;g' {1}".format(
                self.source_dir.replace('/', '\/'),
                gprof_file_path
            )
        )

        return returncode
