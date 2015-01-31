import os, statistics, subprocess, datetime, csv, sys
from optparse import make_option
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

import networkx as nx

from attacksurfacemeter.call_graph import CallGraph
from loaders.cflow_loader import CflowLoader
from loaders.gprof_loader import GprofLoader

from app.models import *
from app import constants
from app import gitapi


class Command(BaseCommand):
    # TODO: Add help text to the options.
    option_list = BaseCommand.option_list + (
        make_option('-r', '--repository-path',
                    dest='repository_path',
                    help='repository-path HELP.'),
        make_option('-w', '--workspace-path',
                    dest='workspace_path',
                    default=os.path.dirname(__file__),
                    help='workspace-path HELP.'),
        make_option('-n', '--rev-num',
                    dest='rev_num',
                    default=None,
                    help='rev-num HELP.'),
        make_option('-t', '--rev-type',
                    dest='rev_type',
                    default='t',
                    help='rev-type HELP.'),
    )
    help = 'loaddb HELP.'

    def handle(self, *args, **options):
        self.validate_arguments(**options)

        revisions = None
        if self.rev_num:
            revisions = Revision.objects.filter(number=self.rev_num, type=self.rev_type)
        else:
            revisions = Revision.objects.filter(is_loaded=False)

        for revision in revisions:
            self.mine(revision)

    def validate_arguments(self, **options):
        self.verbosity = int(options.get('verbosity'))
        self.repository_path = options.get('repository_path')
        self.workspace_path = options.get('workspace_path')
        self.rev_num = options.get('rev_num')
        self.rev_type = options.get('rev_type')

        if not os.path.exists(os.path.join(self.repository_path, '.git')):
            raise CommandError('%s is not a git repository.' % self.repository_path)

        if not constants.RE_REV_NUM.match(self.rev_num):
            raise CommandError('%s is not a valid revision number.' % self.rev_num)

        if self.rev_type not in ['t', 'b']:
            raise CommandError('%s is not a valid revision type.' % self.rev_type)

    def mine(self, revision):
        print('Mining', revision.number)

        # TODO : REMOVE
        start = datetime.datetime.now()

        vuln_funcs = self.get_vulnerable_functions(revision)
        func_sloc = self.get_function_sloc(revision)

        call_graph = self.get_call_graph(revision)

        attack_surface_betweenness = nx.betweenness_centrality(call_graph.attack_surface_graph, endpoints=True)

        # TODO : REMOVE
        index = 1
        total = len(call_graph.nodes)
        with transaction.atomic():
            for node in call_graph.nodes:
                # TODO : REMOVE
                percent = index / total
                self.indicate_progress(percent)
                index += 1

                function = Function()

                function.revision = revision
                function.name = node.function_name
                function.file = node.function_signature
                function.is_entry = node in call_graph.entry_points
                function.is_exit = node in call_graph.exit_points
                function.is_vulnerable = \
                    (
                        node.function_signature in vuln_funcs and
                        node.function_name in vuln_funcs[node.function_signature]
                    )

                # Fully qualified name of the node in the form function_name@file_name
                fq_name = '%s@%s' % (node.function_name, node.function_signature)
                if fq_name in func_sloc:
                    function.sloc = func_sloc[fq_name]

                if node in call_graph.attack_surface_graph_nodes:
                    metrics = call_graph.get_entry_surface_metrics(node)
                    function.proximity_to_entry = metrics['proximity']
                    function.surface_coupling_with_entry = metrics['surface_coupling']

                    metrics = call_graph.get_exit_surface_metrics(node)
                    function.proximity_to_exit = metrics['proximity']
                    function.surface_coupling_with_exit = metrics['surface_coupling']

                if node in attack_surface_betweenness:
                    function.attack_surface_betweenness = attack_surface_betweenness[node]

                function.save()

                if function.is_entry:
                    enpr = Reachability()
                    enpr.type = constants.RT_EN
                    enpr.function = function
                    enpr.value = call_graph.get_entry_point_reachability(node)
                    enpr.save()

                    senpr_within_depth_one = Reachability()
                    senpr_within_depth_one.type = constants.RT_SHEN_ONE
                    senpr_within_depth_one.function = function
                    senpr_within_depth_one.value = call_graph.get_entry_point_reachability(node)
                    senpr_within_depth_one.save()

                    senpr_within_depth_two = Reachability()
                    senpr_within_depth_two.type = constants.RT_SHEN_TWO
                    senpr_within_depth_two.function = function
                    senpr_within_depth_two.value = call_graph.get_entry_point_reachability(node)
                    senpr_within_depth_two.save()

                if function.is_exit:
                    expr = Reachability()
                    expr.type = constants.RT_EX
                    expr.function = function
                    expr.value = call_graph.get_exit_point_reachability(node)
                    expr.save()

            revision.num_entry_points = len(call_graph.entry_points)
            revision.num_exit_points = len(call_graph.exit_points)
            revision.num_functions = len(call_graph.nodes)
            revision.num_attack_surface_functions = len(call_graph.attack_surface_graph_nodes)
            revision.is_loaded = True
            revision.save()

        # TODO : REMOVE
        print()
        print('Start\t', start)
        print('Stop\t', datetime.datetime.now())

    def get_call_graph(self, revision):
        cflow_file = os.path.join(self.workspace_path,
                                  constants.CALLGRAPH_FILE_PATTERN % (revision.type, revision.number, 'cflow'))
        gprof_file = os.path.join(self.workspace_path,
                                  constants.CALLGRAPH_FILE_PATTERN % (revision.type, revision.number, 'gprof'))

        if not os.path.exists(cflow_file) or not os.path.exists(gprof_file):
            self.generate_profile_info(revision, cflow_file, gprof_file)

        cfl = CflowLoader(cflow_file, True)
        gpl = GprofLoader(gprof_file, False)

        return CallGraph.from_merge(CallGraph.from_loader(cfl), CallGraph.from_loader(gpl))

    def generate_profile_info(self, revision, cflow_file, gprof_file):
        repo = gitapi.Repo(self.repository_path)

        self.write('Resetting repository.')
        repo.git_clean()
        repo.git_checkout('master')
        repo.git_pull()
        self.write('Done resetting repository to master.')

        if not os.path.exists(self.workspace_path):
            os.makedirs(self.workspace_path)
            self.write('Created directory %s' % self.workspace_path, 2)

        self.write('\nMining revisions\n', 0)

        self.write('Revision\t' + revision.ref)
        self.write('Date\t\t' + revision.date.strftime('%m/%d/%Y'))
        exec_time = ExecutionTime()

        # Step 2 : Checkout revision
        self.write('Checking out ' + revision.ref)

        exec_time.checkout.begin = datetime.datetime.now()
        self.write('Begun At \t' + exec_time.checkout.begin.strftime('%m/%d/%Y %X'), 2)
        repo.git_checkout(revision.ref)
        exec_time.checkout.end = datetime.datetime.now()
        self.write('Ended At \t' + exec_time.checkout.end.strftime('%m/%d/%Y %X'), 2)

        self.write('Done checking out ' + revision.ref + '.')

        # Step 3 : Configure
        self.write('Configuring ffmpeg.')

        exec_time.configure.begin = datetime.datetime.now()
        self.write('Begun At \t' + exec_time.configure.begin.strftime('%m/%d/%Y %X'), 2)
        self.configure(self.repository_path)
        exec_time.configure.end = datetime.datetime.now()
        self.write('Ended At \t' + exec_time.configure.end.strftime('%m/%d/%Y %X'), 2)

        self.write('Done configuring ffmpeg.')

        # Step 4 : Make
        self.write('Making ffmpeg.')

        exec_time.make.begin = datetime.datetime.now()
        self.write('Begun At \t' + exec_time.make.begin.strftime('%m/%d/%Y %X'), 2)
        self.make(self.repository_path)
        exec_time.make.end = datetime.datetime.now()
        self.write('Ended At \t' + exec_time.make.end.strftime('%m/%d/%Y %X'), 2)

        self.write('Done making ffmpeg.')

        # Step 6 : gprof
        self.write('Generating runtime profile information using gprof.')

        exec_time.gprof.begin = datetime.datetime.now()
        self.write('Begun At \t' + exec_time.gprof.begin.strftime('%m/%d/%Y %X'), 2)
        if not os.path.exists(gprof_file):
            self.gprof(gprof_file, self.repository_path)
        else:
            self.write('%s already exists' % gprof_file)
        exec_time.gprof.end = datetime.datetime.now()
        self.write('Ended At \t' + exec_time.gprof.end.strftime('%m/%d/%Y %X'), 2)

        self.write('Done generating runtime profile information using gprof.')

        # Step 7 : cflow
        self.write('Generating static profile information using cflow.')

        exec_time.cflow.begin = datetime.datetime.now()
        self.write('Begun At \t' + exec_time.cflow.begin.strftime('%m/%d/%Y %X'), 2)
        if not os.path.exists(cflow_file):
            self.cflow(cflow_file, self.repository_path)
        else:
            self.write('%s already exists.' % cflow_file)
        exec_time.cflow.end = datetime.datetime.now()
        self.write('Ended At \t' + exec_time.cflow.end.strftime('%m/%d/%Y %X'), 2)

        self.write('Done generating static profile information using cflow.')

        self.write('Execution completed in %.2f minutes.' % exec_time.elapsed, 0)

    def configure(self, path):
        self.__execute__('./configure --extra-cflags=\'-pg\' --extra-ldflags=\'-pg\'', path)

    def make(self, path):
        self.__execute__('make clean', path)
        self.__execute__('make fate-rsync SAMPLES=fate-suite/', path)
        self.__execute__('make fate SAMPLES=fate-suite/', path)

    def gprof(self, out, path):
        self.__execute__('gprof -q -b -l -c -z ffmpeg_g > %s' % out, path)

    def cflow(self, out, path):
        self.__execute__('cflow -b -r `find -name "*.c" -or -name "*.h" | grep -vwE "(tests|doc)"` > %s' % out, path)

    def get_vulnerable_functions(self, revision):
        vuln_fixes = None
        if revision.type == constants.RT_TAG:
            vuln_fixes = CveRevision.objects.filter(revision=revision)
        elif revision.type == constants.RT_BRANCH:
            vuln_fixes = CveRevision.objects.filter(
                revision__number__startswith=revision.number[:revision.number.rfind('.')])

        repo = gitapi.Repo(self.repository_path)
        vuln_funcs = dict()
        for vuln_fix in vuln_fixes.exclude(commit_hash='NA'):
            files_affected = repo.git_diff_tree(vuln_fix.commit_hash).split('\n')
            files_affected = [fa for fa in files_affected if len(fa.strip('\n')) > 0]
            for file_affected in files_affected:
                file_name = os.path.basename(os.path.join(self.repository_path, file_affected))
                if file_name not in vuln_funcs:
                    vuln_funcs[file_name] = set()
                for line in repo.git_patch(vuln_fix.commit_hash, file_affected).split('\n'):
                    match = constants.RE_FUNC_AFFECTED.search(line)
                    if match:
                        vuln_funcs[file_name].add(match.group(1))

        return vuln_funcs

    def get_function_sloc(self, revision):
        sloc_file = os.path.join(self.workspace_path, constants.FUNC_SLOC_FILE_PATTERN % revision.number)
        function_sloc = dict()
        with open(sloc_file, 'r') as _sloc_file:
            reader = csv.reader(_sloc_file)
            for row in reader:
                if 'Function' in row[0]:
                    function_sloc['%s@%s' % (row[1], row[2])] = row[3]

        return function_sloc

    def write(self, message, verbosity=1):
        if verbosity >= self.verbosity:
            self.stdout.write(str(message))

    def indicate_progress(self, percent, bar_length=50):
        sys.stdout.write("\r")
        progress = ""
        for i in range(bar_length):
            if i < int(bar_length * percent):
                progress += "="
            else:
                progress += " "
        sys.stdout.write("[ %s ] %.2f%%" % (progress, percent * 100))
        sys.stdout.flush()

    def __execute__(self, command, path):
        if path:
            os.chdir(path)

        subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)


class Time:
    def __init__(self):
        self.begin = \
            self.end = None

    @property
    def elapsed(self):
        if self.end and self.begin:
            return (self.end - self.begin).total_seconds() / 60
        return 0


class ExecutionTime:
    def __init__(self):
        self.checkout = Time()
        self.configure = Time()
        self.make = Time()
        self.cflow = Time()
        self.gprof = Time()
        self.attacksurfacemeter = Time()

    @property
    def elapsed(self):
        return self.checkout.elapsed + self.configure.elapsed + self.make.elapsed + self.cflow.elapsed + \
               self.gprof.elapsed + self.attacksurfacemeter.elapsed
