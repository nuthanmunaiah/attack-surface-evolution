import csv
import json
import os
import pickle
import re
import shutil
import subprocess as sp
import sqlite3
from urllib import parse

import requests
from attacksurfacemeter.call import Call
from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.environments import Environments
from attacksurfacemeter.granularity import Granularity
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from attacksurfacemeter.loaders.multigprof_loader import MultigprofLoader
from app import constants, errors, helpers
from app.gitapi import Repo

FUNC_SLOC_QUERY_PRIMARY = '''
    SELECT name, file, sloc FROM function WHERE name = ? AND file = ?
'''
FUNC_SLOC_QUERY_SECONDARY = '''
    SELECT name, file, sloc FROM function WHERE name = ?
'''
FILE_SLOC_QUERY = '''
    SELECT name, sloc FROM file WHERE name = ?
'''


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
        self.sloc_dbconn = None
        self.designed_defenses = None
        self.were_vuln = None
        self.become_vuln = None
        self.call_graph = None
        self.granularity = None

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

    def initialize(self, release, granularity):
        self.scratch_dir = os.path.join(
                self.scratch_dir,
                'b{0}'.format(release.branch.version),
                'v{0}'.format(release.version)
            )
        self.release = release
        if granularity == 'function':
            self.granularity = Granularity.FUNC

            # List of functions that were vulnerable (i.e. known to be fixed
            # for a vulnerability in or before the release being analyzed)
            self.were_vuln = [
                    Call(fix.name, fix.file, Environments.C, Granularity.FUNC)
                    for fix in self.release.past_vulnerability_fixes
                ]
            # List of functions that become vulnerable (i.e. known to be fixed
            # for a vulnerability at a time after the release being analyzed)
            self.become_vuln = [
                    Call(fix.name, fix.file, Environments.C, Granularity.FUNC)
                    for fix in self.release.future_vulnerability_fixes
                ]
        elif granularity == 'file':
            self.granularity = Granularity.FILE

            # List of functions that were vulnerable (i.e. known to be fixed
            # for a vulnerability in or before the release being analyzed)
            self.were_vuln = [
                    Call('', fix.file, Environments.C, Granularity.FILE)
                    for fix in self.release.past_vulnerability_fixes
                ]
            # List of functions that become vulnerable (i.e. known to be fixed
            # for a vulnerability at a time after the release being analyzed)
            self.become_vuln = [
                    Call('', fix.file, Environments.C, Granularity.FILE)
                    for fix in self.release.future_vulnerability_fixes
                ]

        self.is_initialized = True

        if self._cflow_exists or self._gprofs_exist:
            self.is_prepared = True

    def prepare(self, processes=1):
        if not self.is_initialized:
            raise Exception('Subject not initialized. Invoke initialize().')

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

        self.load_sloc()
        self.load_defenses()

    def load_call_graph(self, processes=1):
        self.debug('Loading call graph')

        if not self.is_initialized:
            raise Exception('Subject not initialized. Invoke initialize().')

        if not self.is_prepared:
            raise Exception('Subject not prepared. Invoke prepare().')

        self._unpickle_call_graph()
        if not self.call_graph:
            cflow_loader = None
            gprof_loader = None
            if self._cflow_exists:
                cflow_loader = CflowLoader(
                    self.cflow_path, reverse=True,
                    defenses=self.designed_defenses,
                    vulnerabilities=self.were_vuln
                )
            if self._gprofs_exist:
                gprof_loader = MultigprofLoader(
                    self.gprofs_path, processes=processes,
                    reverse=False,
                    defenses=self.designed_defenses,
                    vulnerabilities=self.were_vuln
                )

            if cflow_loader and gprof_loader:
                self.call_graph = CallGraph.from_merge(
                    CallGraph.from_loader(
                        cflow_loader, granularity=self.granularity
                    ),
                    CallGraph.from_loader(
                        gprof_loader, granularity=self.granularity
                    ),
                    fragmentize=True
                )
                print('')
            elif cflow_loader:
                self.call_graph = CallGraph.from_loader(
                    cflow_loader, fragmentize=True,
                    granularity=self.granularity
                )
            elif gprof_loader:
                self.call_graph = CallGraph.from_loader(
                    gprof_loader, fragmentize=True,
                    granularity=self.granularity
                )

            self._pickle_call_graph()

    def assign_page_rank(self, name='page_rank'):
        if not (self.is_initialized and self.is_prepared):
            raise Exception('Subject is not prepared. Invoke prepare().')

        parameters = self._get_parameters()
        self.debug('Parameters: {0}'.format(parameters))

        self.call_graph.assign_weights(parameters['weights'])
        self.call_graph.assign_page_rank(
            name=name, damping=parameters['damping'],
            entry=parameters['personalization']['entry'],
            exit=parameters['personalization']['exit'],
            other=parameters['personalization']['other'],
        )

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
        self.sloc_dbconn = sqlite3.connect(self._sloc_path)

    def get_sloc(self, name, file_):
        result = None
        with sqlite3.connect(self._sloc_path) as connection:
            _cursor = connection.cursor()
            if self.granularity == Granularity.FUNC:
                _cursor.execute(FUNC_SLOC_QUERY_PRIMARY, (name, file_))
                _rows = _cursor.fetchall()
                if len(_rows) == 1:
                    result = _rows[0][2]
                else:
                    _cursor.execute(FUNC_SLOC_QUERY_SECONDARY, (name,))
                    _rows = _cursor.fetchall()
                    if len(_rows) == 1:
                        result = _rows[0][2]
            elif self.granularity == Granularity.FILE:
                _cursor.execute(FILE_SLOC_QUERY, (file_,))
                _rows = _cursor.fetchall()
                if len(_rows) == 1:
                    result = _rows[0][1]

        return result

    def load_defenses(self):
        self.debug('Loading designed defenses')
        self._download_defenses_file()
        if os.path.getsize(self._defenses_path) > 0:
            self.designed_defenses = list()
            with open(self._defenses_path, 'r') as _defenses_file:
                reader = csv.reader(_defenses_file)
                for row in reader:
                    if self.granularity == Granularity.FUNC:
                        self.designed_defenses.append(Call(
                            row[0], row[1], Environments.C, Granularity.FUNC
                        ))
                    elif self.granularity == Granularity.FILE:
                        self.designed_defenses.append(Call(
                            '', row[1], Environments.C, Granularity.FILE
                        ))
            self.debug('Loaded {0} designed defenses'.format(
                len(self.designed_defenses)
            ))

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

    def _get_parameters(self):
        with open(self._parameters_path, 'r') as file_:
            return json.load(file_)

    def _download_sloc_file(self):
        self.debug('Downloading function SLOC file {0}'.format(
            self._sloc_url
        ))
        self._download(self._sloc_url, self._sloc_path, binary=True)

    def _download_defenses_file(self):
        self.debug('Downloading designed defenses file {0}'.format(
            self._defenses_url
        ))
        self._download(
            self._defenses_url, self._defenses_path
        )

    def _download(self, url, destination, binary=False):
        if os.path.isfile(destination):
            self.debug('{0} already exists'.format(destination))
            return

        response = requests.get(url, stream=True)
        if response.status_code != 200:
            raise Exception(
                    '[HTTP {0}] Downloading {1} failed'.format(
                        response.status_code, url
                    )
                )

        if binary:
            with open(destination, 'wb') as file_:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, file_)
        else:
            with open(destination, 'w') as file_:
                for chunk in response.iter_content(1024, True):
                    file_.write(chunk)
                    file_.flush()

    # Private Properties

    @property
    def _clone_exists(self):
        return os.path.exists(self.source_dir)

    @property
    def _sloc_url(self):
        return (
            self.assets_url + '/sloc/{0}.sqlite'.format(self.release.version)
        )

    @property
    def _sloc_path(self):
        return os.path.join(self.scratch_dir, 'sloc.sqlite')

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
        return os.path.join(
            self.scratch_dir, 'call_graph.{}.pickle'.format(self.granularity)
        )

    @property
    def _pickle_exists(self):
        return os.path.exists(self._pickle_path)

    @property
    def _parameters_path(self):
        return helpers.get_absolute_path(
            'app/assets/data/{0}/parameters.json'.format(self.name)
        )
