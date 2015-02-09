import os, statistics, subprocess, datetime, csv, sys, re
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
                    default='b',
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

        if revisions.count() == 0:
            raise CommandError('No revisions to mine. Aborting.')
        else:
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

        vulnerability_source = set()
        vulnerability_sink = set()
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
                    function.is_connected_to_attack_surface = True

                    metrics = call_graph.get_entry_surface_metrics(node)
                    function.proximity_to_entry = metrics['proximity']
                    function.surface_coupling_with_entry = metrics['surface_coupling']

                    if function.is_vulnerable and metrics['points']:
                        for point in metrics['points']:
                            vulnerability_source.add(point)

                    metrics = call_graph.get_exit_surface_metrics(node)
                    function.proximity_to_exit = metrics['proximity']
                    function.surface_coupling_with_exit = metrics['surface_coupling']

                    if function.is_vulnerable and metrics['points']:
                        for point in metrics['points']:
                            vulnerability_sink.add(point)

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
                    senpr_within_depth_one.value = call_graph.get_shallow_entry_point_reachability(node)
                    senpr_within_depth_one.save()

                    senpr_within_depth_two = Reachability()
                    senpr_within_depth_two.type = constants.RT_SHEN_TWO
                    senpr_within_depth_two.function = function
                    senpr_within_depth_two.value = call_graph.get_shallow_entry_point_reachability(node, depth=2)
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

            for item in vulnerability_source:
                function = Function.objects.get(name=item.function_name, file=item.function_signature)
                function.is_vulnerability_source = True
                function.save()

            for item in vulnerability_sink:
                function = Function.objects.get(name=item.function_name, file=item.function_signature)
                function.is_vulnerability_sink = True
                function.save()

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
            raise CommandError('Call graphs file(s) not found at %s.' % self.workspace_path)

        cfl = CflowLoader(cflow_file, True)
        gpl = GprofLoader(gprof_file, False)

        call_graph = CallGraph.from_merge(CallGraph.from_loader(cfl), CallGraph.from_loader(gpl))
        call_graph.remove_standard_library_calls()

        return call_graph

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
        re_function = re.compile('^([^\(]*)')
        sloc_file = os.path.join(self.workspace_path, constants.FUNC_SLOC_FILE_PATTERN % revision.number)
        function_sloc = dict()
        with open(sloc_file, 'r') as _sloc_file:
            reader = csv.reader(_sloc_file)
            next(reader)  # Skipping the header
            for row in reader:
                function = re_function.match(row[1]).group(1)
                file = row[0][row[0].rfind('\\') + 1:]
                function_sloc['%s@%s' % (function, file)] = row[3]

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