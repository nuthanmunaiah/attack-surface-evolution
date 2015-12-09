import csv
import os
import pickle
import re
import subprocess as sp
from urllib import parse

import requests
from attacksurfacemeter.call import Call
from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.environments import Environments
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from attacksurfacemeter.loaders.multigprof_loader import MultigprofLoader
from app import constants, errors, helpers
from app.gitapi import Repo


class Subject(object):
    def __init__(self, name, remote, scratch_root):
        self.name = name
        self.remote = remote

        scratch_root = os.path.expanduser(scratch_root)
        self.scratch_dir = os.path.join(scratch_root, self.name)

        self.assets_url = '{0}/{1}'.format(
                constants.ASSETS_ROOT_URL, self.name
            )

        self.release = None
        self.repo = None
        self.function_sloc = None
        self.designed_defenses = None
        self.call_graph = None

        self.is_initialized = False
        self.is_prepared = False

    def clone(self):
        if not self._clone_exists:
            self.debug('Cloning {0}'.format(self.remote))
            self.repo = Repo.git_clone(self.remote, self.source_dir)
        else:
            self.debug(
                    'Attaching to existing clone {0}'.format(self.source_dir)
                )
            self.repo = Repo(self.source_dir)

    def checkout(self, reference):
        if self.repo is None:
            self.clone()
        self.debug('Checking out {0}'.format(reference))
        self.repo.git_checkout(reference)

    def configure(self, options):
        raise NotImplementedError

    def make(self, processes=1):
        raise NotImplementedError

    def test(self, processes=1):
        raise NotImplementedError

    def cflow(self):
        self.debug(
                'Generating call graph for {0} using cflow'.format(self.name)
            )
        cmd = (
            'cflow -b -r '
            '`find -name "*.c" -or -name "*.h" | grep -vwE "(tests|doc)"`'
        )

        with open(self.cflow_path, 'w+') as _cflow_file:
            return self.execute(cmd, stdout=_cflow_file)

    def gprof(self, index):
        self.debug(
                'Generating call graph for {0} using gprof'.format(self.name)
            )
        gmon_file_name = self.gmons_name[index]
        gmon_file_path = os.path.join(self.gmons_dir, gmon_file_name)
        gprof_file_path = os.path.join(
                self.gprofs_dir, '{0}.txt'.format(gmon_file_name)
            )
        return self.__gprof__(gmon_file_path, gprof_file_path)

    def __gprof__(self, gmon_file_path, gprof_file_path):
        raise NotImplementedError

    def initialize(self, release):
        self.scratch_dir = os.path.join(
                self.scratch_dir,
                'b{0}'.format(release.branch.version),
                'v{0}'.format(release.version)
            )
        self.release = release
        self.is_initialized = True

        if self._cflow_exists or self._gprofs_exist:
            self.is_prepared = True

    def prepare(self, processes=1):
        if not self.is_initialized:
            raise Exception('Subject not initialized. Invoke initialize().')

        self.load_sloc()
        self.load_defenses()

        if not self.is_prepared:
            self.clone()
            self.checkout(self.release.reference)

            return_code = self.configure(
                    options=self.release.branch.configure_options
                )
            if return_code != 0:
                raise Exception('configure() returned {0}'.format(return_code))
            return_code = self.make(processes)
            if return_code != 0:
                raise Exception('make() returned {0}'.format(return_code))
            return_code = self.cflow()
            if return_code != 0:
                raise Exception('cflow() returned {0}'.format(return_code))
            return_code = self.test(processes)
            if return_code != 0:
                raise Exception('test() returned {0}'.format(return_code))

            self.is_prepared = True

    def load_call_graph(self, were_vulnerable, processes=1):
        self.debug('Loading call graph')

        if not self.is_initialized:
            raise Exception('Subject not initialized. Invoke initialize().')

        if not self.is_prepared:
            raise Exception('Subject not prepared. Invoked prepare().')

        self._unpickle_call_graph()
        if not self.call_graph:
            cflow_loader = None
            gprof_loader = None
            if self._cflow_exists:
                cflow_loader = CflowLoader(
                    self.cflow_path, reverse=True,
                    defenses=self.designed_defenses,
                    vulnerabilities=were_vulnerable
                )
            if self._gprofs_exist:
                gprof_loader = MultigprofLoader(
                    self.gprofs_path, processes=processes,
                    reverse=False,
                    defenses=self.designed_defenses,
                    vulnerabilities=were_vulnerable
                )

            if cflow_loader and gprof_loader:
                self.call_graph = CallGraph.from_merge(
                    CallGraph.from_loader(cflow_loader),
                    CallGraph.from_loader(gprof_loader),
                    fragmentize=True
                )
                print('')
            elif cflow_loader:
                self.call_graph = CallGraph.from_loader(
                    cflow_loader, fragmentize=True
                )
            elif gprof_loader:
                self.call_graph = CallGraph.from_loader(
                    gprof_loader, fragmentize=True
                )

            self._pickle_call_graph()

    def _pickle_call_graph(self):
        self.debug(
                'Pickling call graph to {0}'.format(self._pickle_path)
            )
        with open(self._pickle_path, 'wb') as file_:
            pickle.dump(self.call_graph, file_)

    def _unpickle_call_graph(self):
        self.debug(
                'Unpickling call graph from {0}'.format(self._pickle_path)
            )
        if self._pickle_exists:
            with open(self._pickle_path, 'rb') as file_:
                self.call_graph = pickle.load(file_)

    def get_absolute_path(self, name):
        return os.path.join(self.source_dir, name)

    def load_sloc(self):
        self.debug('Loading function SLOC')
        self._download_sloc_file()
        if os.path.getsize(self._sloc_path) > 0:
            re_function = re.compile('^([^\(]*)')

            self.function_sloc = dict()
            with open(self._sloc_path, 'r') as _sloc_file:
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

    def load_defenses(self):
        self.debug('Loading designed defenses')
        self._download_defenses_file()
        if os.path.getsize(self._defenses_path) > 0:
            self.designed_defenses = list()
            with open(self._defenses_path, 'r') as _defenses_file:
                reader = csv.reader(_defenses_file)
                for row in reader:
                    self.designed_defenses.append(
                        Call(row[0], row[1], Environments.C)
                    )
            self.debug(
                    'Loaded {0} designed defenses'.format(
                        len(self.designed_defenses)
                    )
                )

    def get_functions(self, shas):
        functions = list()

        for sha in shas:
            for fpath in self.repo.get_files_changed(sha):
                fpath = self.get_absolute_path(fpath)
                fpath = fpath.replace(self.source_dir, '.')

                for func in self.repo.get_functions_changed(sha, file=fpath):
                    functions.append((func, fpath))

        return functions

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

        self.debug(cmd)

        if not cwd:
            cwd = self.source_dir

        process = sp.Popen(
            cmd, stdout=stdout, stderr=stderr, cwd=cwd, shell=True
        )

        return process.wait()

    def debug(self, message, line=False):
        helpers.debug(message, line)

    @property
    def source_dir(self):
        return os.path.join(self.scratch_dir, 'src')

    @property
    def cflow_path(self):
        return os.path.join(self.scratch_dir, 'cflow.txt')

    @property
    def gprofs_dir(self):
        return os.path.join(self.scratch_dir, 'gprof')

    @property
    def gprofs_path(self):
        gprof_files = None
        if os.path.exists(self.gprofs_dir):
            gprof_files = [
                    os.path.join(self.gprofs_dir, gprof_file_name)
                    for gprof_file_name in os.listdir(self.gprofs_dir)
                ]
            gprof_files.sort()
        return gprof_files

    @property
    def gmons_dir(self):
        return os.path.join(self.source_dir, 'gmon')

    @property
    def gmons_name(self):
        return os.listdir(self.gmons_dir)

    # Private Members

    # Private Methods

    def _clean_up(self):
        raise NotImplementedError

    def _download_sloc_file(self):
        self.debug('Downloading function SLOC file {0}'.format(
            self._sloc_url
        ))
        self._download(self._sloc_url, self._sloc_path)

    def _download_defenses_file(self):
        self.debug('Downloading designed defenses file {0}'.format(
            self._defenses_url
        ))
        self._download(
            self._defenses_url, self._defenses_path
        )

    def _download(self, url, destination):
        with open(destination, 'w+') as file_:
            response = requests.get(url, stream=True)
            for chunk in response.iter_content(1024, True):
                file_.write(chunk)
                file_.flush()

    def _get_asset_name(self):
        if self.release is not None:
            return '{0}.csv'.format(self.release.version)
        return '{0}.csv'.format(self.name)

    # Private Properties

    @property
    def _clone_exists(self):
        return os.path.exists(self.source_dir)

    @property
    def _sloc_url(self):
        return self.assets_url + '/sloc/{0}'.format(self._get_asset_name())

    @property
    def _sloc_path(self):
        return os.path.join(self.scratch_dir, 'sloc.csv')

    @property
    def _defenses_url(self):
        return self.assets_url + '/defenses/{0}.csv'.format(self.name)

    @property
    def _defenses_path(self):
        return os.path.join(self.scratch_dir, 'defenses.csv')

    @property
    def _cflow_exists(self):
        return os.path.exists(self.cflow_path)

    @property
    def _gprofs_exist(self):
        return bool(self.gprofs_path)

    @property
    def _pickle_path(self):
        return os.path.join(self.scratch_dir, 'call_graph.pickle')

    @property
    def _pickle_exists(self):
        return os.path.exists(self._pickle_path)
