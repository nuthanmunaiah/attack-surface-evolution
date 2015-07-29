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
        return 0

    def make(self):
        return 0

    def test(self):
        return 0

    def __gprof__(self, gmon_file_path, gprof_file_path):
        return 0
