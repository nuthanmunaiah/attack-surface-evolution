import csv
import os
import re
import subprocess as sp
import threading
import hashlib
from urllib import parse

import requests
from attacksurfacemeter.call import Call
from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.environments import Environments
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from attacksurfacemeter.loaders.multigprof_loader import MultigprofLoader
from app import errors, helpers, utilities
from app.gitapi import Repo


class Subject(object):
    def __init__(
        self, name, clone_url, configure_options, processes=1,
        git_reference=None, remote_url=None, scratch_root='/tmp'
    ):

        self.name = name
        self.clone_url = clone_url
        self.configure_options = configure_options
        self.processes = processes
        self.git_reference = git_reference
        self.remote_url = remote_url
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
        self.designed_defenses = None

    def clone(self):
        if not self.__clone_exists__:
            self.__dbug__('Cloning {0}'.format(self.clone_url))
            self.repo = Repo.git_clone(self.clone_url, self.source_dir)
            return True
        self.__dbug__(
            'Attaching to existing clone at {0}'.format(self.source_dir)
        )
        self.repo = Repo(self.source_dir)
        return False

    def checkout(self):
        if self.git_reference:
            self.__dbug__('Checking out {0}'.format(self.git_reference))
            self.repo.git_checkout(self.git_reference)

    def configure(self):
        raise NotImplementedError

    def make(self):
        raise NotImplementedError

    def test(self):
        raise NotImplementedError

    def cflow(self):
        raise NotImplementedError

    def gprof(self, index=None):
        raise NotImplementedError

    def initialize(self):
        if not self.initialized:
            cloned = self.clone()
            if cloned:
                self.checkout()

            self.initialized = True

    def prepare(self):
        if not (self.__cflow_file_exists__ and self.__gprof_files_exist__):
            self.initialize()
            return_code = self.configure()
            if return_code != 0:
                raise Exception('configure() returned {0}'.format(return_code))
            return_code = self.make()
            if return_code != 0:
                raise Exception('make() returned {0}'.format(return_code))
            return_code = self.cflow()
            if return_code != 0:
                raise Exception('cflow() returned {0}'.format(return_code))
            return_code = self.test()
            if return_code != 0:
                raise Exception('test() returned {0}'.format(return_code))

        self.prepared = True

    def load_call_graph(self):
        self.__dbug__('Loading call graph')
        if not self.prepared:
            raise errors.SubjectNotPreparedError(
                'prepare() must be invoked before load_call_graph()'
            )

        if not self.call_graph:
            cflow_loader = CflowLoader(
                self.cflow_file_path, reverse=True,
                defenses=self.designed_defenses,
                vulnerabilities=self.vulnerable_functions
            )
            gprof_loader = MultigprofLoader(
                self.gprof_files_path, processes=self.processes, reverse=False,
                defenses=self.designed_defenses,
                vulnerabilities=self.vulnerable_functions
            )

            self.call_graph = CallGraph.from_merge(
                CallGraph.from_loader(cflow_loader),
                CallGraph.from_loader(gprof_loader),
                fragmentize=True
            )
            print('')
            self.__dbug__('Assigning edge weights')
            self.call_graph.assign_weights()
            self.__dbug__('Assigning page ranks')
            self.call_graph.assign_page_rank(name='page_rank')

    def get_absolute_path(self, name):
        return os.path.join(self.source_dir, name)

    def load_function_sloc(self):
        self.__dbug__('Loading function SLOC')
        self.__download_sloc_file__()
        if (
            not self.function_sloc and
            os.path.getsize(self.__sloc_file_path__) > 0
        ):
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
        self.__dbug__('Loading vulnerable functions')
        if not self.vulnerable_functions and commit_hashes:
            self.vulnerable_functions = list()
            for commit_hash in commit_hashes:
                for file_ in self.repo.get_files_changed(commit_hash):
                    file_path = self.get_absolute_path(file_)
                    file_path = file_path.replace(self.source_dir, '.')

                    functions = self.repo.get_functions_changed(
                        commit_hash, file=file_
                    )
                    for function in functions:
                        self.vulnerable_functions.append(
                            Call(function, file_path, Environments.C)
                        )

    def load_designed_defenses(self):
        self.__dbug__('Loading designed defenses')
        self.__download_defenses_file__()
        if (
            not self.designed_defenses and
            os.path.getsize(self.__defenses_file_path__) > 0
        ):
            self.designed_defenses = list()
            with open(self.__defenses_file_path__, 'r') as _defenses_file:
                reader = csv.reader(_defenses_file)
                for row in reader:
                    self.designed_defenses.append(
                        Call(row[0], row[1], Environments.C)
                    )

    def is_function_vulnerable(self, name, in_file):
        if self.vulnerable_functions:
            if in_file in self.vulnerable_functions:
                return name in self.vulnerable_functions[in_file]
        return False

    def execute(self, cmd, cwd=None, stdout=sp.DEVNULL, stderr=sp.DEVNULL):
        # Debugging override
        if 'DEBUG' in os.environ:
            if stdout == sp.DEVNULL:
                stdout = None
            if stderr == sp.DEVNULL:
                stderr = None

        self.__dbug__(cmd)

        if not cwd:
            cwd = self.source_dir

        process = sp.Popen(
            cmd, stdout=stdout, stderr=stderr, cwd=cwd, shell=True
        )

        return process.wait()

    @property
    def source_dir(self):
        return os.path.join(self.scratch_dir, self.uuid, 'src')

    @property
    def cflow_file_path(self):
        return os.path.join(self.scratch_dir, self.uuid, 'cflow.txt')

    @property
    def gprof_files_dir(self):
        return os.path.join(self.scratch_dir, self.uuid, 'gprof')

    @property
    def gprof_files_path(self):
        gprof_files = [
            os.path.join(
                self.gprof_files_dir,
                gprof_file_name
            )
            for gprof_file_name in os.listdir(self.gprof_files_dir)
        ]
        gprof_files.sort()
        return gprof_files

    @property
    def gmon_files_dir(self):
        return os.path.join(self.source_dir, 'gmon')

    @property
    def gmon_files_name(self):
        return os.listdir(self.gmon_files_dir)

    def __clean_up__(self):
        raise NotImplementedError

    def __download_sloc_file__(self):
        self.__dbug__('Downloading function SLOC file {0}'.format(
            self.__sloc_file_url__
        ))
        if (self.__sloc_file_url__ and not self.__sloc_file_exists__):
            with open(self.__sloc_file_path__, 'w+') as file_:
                response = requests.get(self.__sloc_file_url__, stream=True)
                for chunk in response.iter_content(1024, True):
                    file_.write(chunk)
                    file_.flush()

    def __download_defenses_file__(self):
        self.__dbug__('Downloading designed defenses file {0}'.format(
            self.__defenses_file_url__
        ))
        if (self.__defenses_file_url__ and not self.__defenses_file_exists__):
            with open(self.__defenses_file_path__, 'w+') as file_:
                response = requests.get(
                    self.__defenses_file_url__, stream=True
                )
                for chunk in response.iter_content(1024, True):
                    file_.write(chunk)
                    file_.flush()

    def __dbug__(self, message, line=False):
        utilities.debug(message, line)

    @property
    def __sloc_file_url__(self):
        url = None

        if self.remote_url:
            sloc_file_name = '{0}.csv'.format(self.name)

            if self.git_reference:
                sloc_file_name = '{0}.{1}'.format(
                    '%d.%d.%d' % helpers.get_version_components(
                        self.git_reference
                    ),
                    sloc_file_name
                )

            url = parse.urljoin(
                self.remote_url, 'sloc/{0}'.format(sloc_file_name)
            )

        return url

    @property
    def __sloc_file_path__(self):
        return os.path.join(self.scratch_dir, self.uuid, 'sloc.csv')

    @property
    def __sloc_file_exists__(self):
        return os.path.exists(self.__sloc_file_path__)

    @property
    def __defenses_file_url__(self):
        url = None

        if self.remote_url:
            defenses_file_name = '{0}.csv'.format(self.name)
            url = parse.urljoin(
                self.remote_url, 'defenses/{0}'.format(defenses_file_name)
            )

        return url

    @property
    def __defenses_file_path__(self):
        return os.path.join(self.scratch_dir, self.uuid, 'defenses.csv')

    @property
    def __defenses_file_exists__(self):
        return os.path.exists(self.__defenses_file_path__)

    @property
    def __cflow_file_exists__(self):
        return os.path.exists(self.cflow_file_path)

    @property
    def __gprof_files_exist__(self):
        if self.gprof_files_path:
            return True
        return False

    @property
    def __clone_exists__(self):
        return os.path.exists(self.source_dir)
