import os, statistics, subprocess, datetime, csv, sys, threading
from optparse import make_option
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

import networkx as nx

from attacksurfacemeter.call_graph import CallGraph
from loaders.cflow_loader import CflowLoader
from loaders.gprof_loader import GprofLoader

from app import models, constants, gitapi


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
                    default='b',
                    help='rev-type HELP.'),
    )
    help = 'loaddb HELP.'

    def handle(self, *args, **options):
        self.validate_arguments(**options)

        revisions = None
        if self.rev_num:
            revisions = models.Revision.objects.filter(number=self.rev_num, type=self.rev_type)
        else:
            revisions = models.Revision.objects.filter(is_loaded=False)

        if revisions.count() == 0:
            raise CommandError('No revisions to mine. Aborting.')
        else:
            utilities = Utilities(self.repository_path, self.workspace_path)
            for revision in revisions:
                rev = Revision(revision, utilities)
                rev.init()
                rev.mine()

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

    def write(self, message, verbosity=1):
        if verbosity >= self.verbosity:
            self.stdout.write(str(message))


class Revision(object):
    def __init__(self, revision, utilities):
        if not isinstance(revision, models.Revision):
            raise CommandError('Argument revision should be of type app.models.Revision.')

        self.revision = revision
        self.utilities = utilities
        self.semaphore = threading.BoundedSemaphore(value=25)
        self.dblock = threading.Lock()

    def init(self):
        self.vuln_funcs = self.utilities.get_vulnerable_functions(self.revision)
        self.func_sloc = self.utilities.get_function_sloc(self.revision)
        self.call_graph = self.utilities.get_call_graph(self.revision)
        self.attack_surface_betweenness = nx.betweenness_centrality(self.call_graph.attack_surface_graph,
                                                                    endpoints=True)

    def mine(self):
        print('Mining', self.revision.number)

        # TODO : REMOVE
        start = datetime.datetime.now()

        index = 1
        total = len(self.call_graph.nodes)
        with transaction.atomic():
            for node in self.call_graph.nodes:
                self.semaphore.acquire()
                thread = threading.Thread(target=self.__process_node__, args=(node,))
                thread.start()

                percent = index / total
                index += 1
                self.utilities.indicate_progress(percent)

            self.revision.num_entry_points = len(self.call_graph.entry_points)
            self.revision.num_exit_points = len(self.call_graph.exit_points)
            self.revision.num_functions = len(self.call_graph.nodes)
            self.revision.num_attack_surface_functions = len(self.call_graph.attack_surface_graph_nodes)
            self.revision.is_loaded = True
            self.revision.save()

        # TODO : REMOVE
        print()
        print('Start\t', start)
        print('Stop\t', datetime.datetime.now())

    def __process_node__(self, node):
        try:
            function = models.Function()
            function.revision = self.revision
            function.name = node.function_name
            function.file = node.function_signature
            function.is_entry = node in self.call_graph.entry_points
            function.is_exit = node in self.call_graph.exit_points
            function.is_vulnerable = \
                (
                    node.function_signature in self.vuln_funcs and
                    node.function_name in self.vuln_funcs[node.function_signature]
                )

            # Fully qualified name of the node in the form function_name@file_name
            func_name = '%s@%s' % (node.function_name, node.function_signature)
            if func_name in self.func_sloc:
                function.sloc = self.func_sloc[func_name]

            if node in self.call_graph.attack_surface_graph_nodes:
                metrics = self.call_graph.get_entry_surface_metrics(node)
                function.proximity_to_entry = metrics['proximity']
                function.surface_coupling_with_entry = metrics['surface_coupling']

                metrics = self.call_graph.get_exit_surface_metrics(node)
                function.proximity_to_exit = metrics['proximity']
                function.surface_coupling_with_exit = metrics['surface_coupling']

            if node in self.attack_surface_betweenness:
                function.attack_surface_betweenness = self.attack_surface_betweenness[node]

            with self.dblock:
                function.save()

            if function.is_entry:
                enpr = models.Reachability()
                enpr.type = constants.RT_EN
                enpr.function = function
                enpr.value = self.call_graph.get_entry_point_reachability(node)

                senpr_within_depth_one = models.Reachability()
                senpr_within_depth_one.type = constants.RT_SHEN_ONE
                senpr_within_depth_one.function = function
                senpr_within_depth_one.value = self.call_graph.get_entry_point_reachability(node)

                senpr_within_depth_two = models.Reachability()
                senpr_within_depth_two.type = constants.RT_SHEN_TWO
                senpr_within_depth_two.function = function
                senpr_within_depth_two.value = self.call_graph.get_entry_point_reachability(node)

                with self.dblock:
                    enpr.save()
                    senpr_within_depth_one.save()
                    senpr_within_depth_two.save()

            if function.is_exit:
                expr = models.Reachability()
                expr.type = constants.RT_EX
                expr.function = function
                expr.value = self.call_graph.get_exit_point_reachability(node)

                with self.dblock:
                    expr.save()
        finally:
            self.semaphore.release()


class Utilities(object):
    def __init__(self, repository_path, workspace_path):
        self.repository_path = repository_path
        self.workspace_path = workspace_path

    def get_vulnerable_functions(self, revision):
        vuln_fixes = None
        if revision.type == constants.RT_TAG:
            vuln_fixes = models.CveRevision.objects.filter(revision=revision)
        elif revision.type == constants.RT_BRANCH:
            vuln_fixes = models.CveRevision.objects.filter(
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

        if not os.path.exists(sloc_file):
            raise CommandError('%s not found.' % sloc_file)

        function_sloc = dict()
        with open(sloc_file, 'r') as _sloc_file:
            reader = csv.reader(_sloc_file)
            for row in reader:
                if 'Function' in row[0]:
                    function_sloc['%s@%s' % (row[1], row[2])] = row[3]

        return function_sloc

    def get_call_graph(self, revision):
        cflow_file = os.path.join(self.workspace_path,
                                  constants.CALLGRAPH_FILE_PATTERN % (revision.type, revision.number, 'cflow'))
        gprof_file = os.path.join(self.workspace_path,
                                  constants.CALLGRAPH_FILE_PATTERN % (revision.type, revision.number, 'gprof'))

        if not os.path.exists(cflow_file) or not os.path.exists(gprof_file):
            raise CommandError('Call graphs file(s) not found at %s.' % self.workspace_path)

        cfl = CflowLoader(cflow_file, True)
        gpl = GprofLoader(gprof_file, False)

        return CallGraph.from_merge(CallGraph.from_loader(cfl), CallGraph.from_loader(gpl))

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