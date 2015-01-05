import os, statistics, subprocess
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
        make_option('-c', '--callgraph-path',
                    dest='callgraph_path',
                    default=os.path.dirname(__file__),
                    help='callgraph-path HELP.'),
        make_option('-n', '--rev-num',
                    dest='rev_num',
                    default=None,
                    help='rev-num HELP.'),
    )
    help = 'loaddb HELP.'

    def handle(self, *args, **options):
        self.validate_arguments()

        revisions = None
        if self.rev_num:
            revisions = Revision.objects.get(number=self.rev_num)
        else:
            revisions = Revision.objects.all()

        for revision in revisions:
            self.mine(revision)

    def validate_arguments(self):
        self.verbosity = int(options.get('verbosity'))
        self.repository_path = options.get('repository_path')
        self.callgraph_path = options.get('callgraph_path')
        self.rev_num = options.get('rev_num')

        if not os.path.exists(os.path.join(self.repository_path, '.git')):
            raise CommandError('%s is not a git repository.' % self.repository_path)

        if not constants.RE_REV_NUM.match(self.rev_num):
            raise CommandError('%s is not a valid revision number.' % self.rev_num)

    def mine(self, revision):
        vuln_funcs = self.get_vulnerable_functions(revision)
        call_graph = self.get_call_graph(revision)

        with transaction.atomic():
            for node in call_graph.nodes:
                function = Function()

                function.revision = revision
                function.name = node.function_name
                function.file = node.function_signature
                function.is_entry = node in call_graph.entry_points
                function.is_exit = node in call_graph.exit_points
                function.vulnerable = node.function_name in vuln_funcs

                entry_path_lengths = []
                for ep in [ep for ep in call_graph.entry_points if ep != node]:
                    try:
                        if nx.has_path(call_graph.call_graph, source=ep, target=node):
                            entry_path_lengths.append(
                                nx.shortest_path_length(call_graph.call_graph, source=ep, target=node))
                    except KeyError as key_error:
                        print(key_error.args[0].function_name)

                if entry_path_lengths:
                    function.min_dist_to_entry = min(entry_path_lengths)
                    function.max_dist_to_entry = max(entry_path_lengths)
                    function.avg_dist_to_entry = statistics.mean(entry_path_lengths)
                    function.num_entry_points = len(entry_path_lengths)

                exit_path_lengths = []
                for exp in [exp for exp in call_graph.exit_points if exp != node]:
                    try:
                        if nx.has_path(call_graph.call_graph, source=node, target=exp):
                            exit_path_lengths.append(
                                nx.shortest_path_length(call_graph.call_graph, source=node, target=exp))
                    except KeyError as key_error:
                        print(key_error.args[0].function_name)

                if exit_path_lengths:
                    function.min_dist_to_exit = min(exit_path_lengths)
                    function.max_dist_to_exit = max(exit_path_lengths)
                    function.avg_dist_to_exit = statistics.mean(exit_path_lengths)
                    function.num_exit_points = len(exit_path_lengths)

                function.save()

            for ep in call_graph.entry_points:
                function = Function.objects.get(name=ep.function_name, file=ep.function_signature)

                epr = Reachability()
                epr.type = constants.RT_EPR
                epr.function = function
                epr.value = call_graph.get_entry_point_reachability(ep)
                epr.save()

                sr = Reachability()
                sr.type = constants.RT_SEPR
                sr.function = function
                sr.value = call_graph.get_shallow_risk(ep)
                sr.save()

            for exp in call_graph.exit_points:
                expr = Reachability()
                expr.type = constants.RT_EXPR
                expr.function = Function.objects.get(name=ep.function_name, file=ep.function_signature)
                expr.value = call_graph.get_exit_point_reachability(exp)
                expr.save()

    def get_call_graph(self, revision):
        cflow_file = os.path.join(self.callgraph_path,
                                  constants.CALLGRAPH_FILE_PATTERN % (revision.type, revision.number, 'cflow'))
        gprof_file = os.path.join(self.callgraph_path,
                                  constants.CALLGRAPH_FILE_PATTERN % (revision.type, revision.number, 'gprof'))

        if not os.path.exists(_c_file) or not os.path.exists(_g_file):
            self.generate_profile_info(revision, cflow_file, gprof_file)

        cfl = CflowLoader(cflow_file, True)
        gpl = GprofLoader(gprof_file, False)

        return CallGraph.from_merge(CallGraph.from_loader(cfl), CallGraph.from_loader(gpl))

    def generate_profile_info(self, revision, cflow_file, gprof_file):
        repo = gitapi.Repo(self.repository_path)

        write('Resetting repository.')
        repo.git_clean(del_untracked=True)
        repo.git_fetch('origin')
        repo.git_reset('origin/master')
        write('Done resetting repository to master.')

        if not os.path.exists(self.callgraph_path):
            os.makedirs(self.callgraph_path)
            write('Created directory %s' % self.callgraph_path, 2)

        write('\nMining revisions\n', 0)
        time_keeper = TimeKeeper()

        write('Revision\t' + revision.ref)
        write('Date\t\t' + revision.date.strftime('%m/%d/%Y'))
        exec_time = ExecutionTime()

        # Step 2 : Checkout revision
        write('Checking out ' + revision.ref)

        exec_time.checkout.begin = datetime.datetime.now()
        debug('Begun At \t' + exec_time.checkout.begin.strftime('%m/%d/%Y %X'), 2)
        repo.git_checkout(revision.ref)
        exec_time.checkout.end = datetime.datetime.now()
        debug('Ended At \t' + exec_time.checkout.end.strftime('%m/%d/%Y %X'), 2)

        write('Done checking out ' + revision.ref + '.')

        # Step 3 : Configure
        write('Configuring ffmpeg.')

        exec_time.configure.begin = datetime.datetime.now()
        debug('Begun At \t' + exec_time.configure.begin.strftime('%m/%d/%Y %X'), 2)
        self.configure(self.repository_path)
        exec_time.configure.end = datetime.datetime.now()
        debug('Ended At \t' + exec_time.configure.end.strftime('%m/%d/%Y %X'), 2)

        write('Done configuring ffmpeg.')

        # Step 4 : Make
        write('Making ffmpeg.')

        exec_time.make.begin = datetime.datetime.now()
        debug('Begun At \t' + exec_time.make.begin.strftime('%m/%d/%Y %X'), 2)
        self.make(self.repository_path)
        exec_time.make.end = datetime.datetime.now()
        debug('Ended At \t' + exec_time.make.end.strftime('%m/%d/%Y %X'), 2)

        write('Done making ffmpeg.')

        # Step 6 : gprof
        write('Generating runtime profile information using gprof.')

        exec_time.gprof.begin = datetime.datetime.now()
        debug('Begun At \t' + exec_time.gprof.begin.strftime('%m/%d/%Y %X'), 2)
        self.gprof(gprof_file, self.repository_path)
        exec_time.gprof.end = datetime.datetime.now()
        debug('Ended At \t' + exec_time.gprof.end.strftime('%m/%d/%Y %X'), 2)

        write('Done generating runtime profile information using gprof.')

        # Step 7 : cflow
        write('Generating static profile information using cflow.')

        exec_time.cflow.begin = datetime.datetime.now()
        debug('Begun At \t' + exec_time.cflow.begin.strftime('%m/%d/%Y %X'), 2)
        cflow(cflow_file, self.repository_path)
        exec_time.cflow.end = datetime.datetime.now()
        debug('Ended At \t' + exec_time.cflow.end.strftime('%m/%d/%Y %X'), 2)

        write('Done generating static profile information using cflow.')

        write('Execution completed in %.2f minutes.' % exec_time.elapsed, 0)

    def configure(path):
        self.__execute__('./configure --extra-cflags=\'-pg\' --extra-ldflags=\'-pg\'', path)

    def make(path):
        self.__execute__('make clean', path)
        self.__execute__('make fate-rsync SAMPLES=fate-suite/', path)
        self.__execute__('make fate SAMPLES=fate-suite/', path)

    def gprof(out, path):
        self.__execute__('gprof -q -b -l -c -z ffmpeg_g > %s' % out, path)

    def cflow(out, path):
        self.__execute__('cflow -b `find -name "*.c" -or -name "*.h"` > %s' % out, path)

    def get_vulnerable_functions(self, revision):
        repo = gitapi.Repo(self.repository_path)

        vuln_funcs = set()
        for vuln_fix in CveRevision.objects.filter(revision=revision):
            if vuln_fix.commit_hash != 'NA':
                for line in repo.git_path_log(vuln_fix.commit_hash).split('\n'):
                    match = constants.RE_FUNC_AFFECTED.match(line)
                    if match:
                        vuln_funcs.add(match.group(3))

        return vuln_funcs

    def write(self, message, verbosity=1):
        if verbosity >= self.verbosity:
            self.stdout.write(str(message))

    def __execute__(command, path):
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