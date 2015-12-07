import datetime
import multiprocessing
import operator
import os
import sys
import shutil

from optparse import make_option, OptionValueError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

import networkx as nx

from app import constants
from app.errors import InvalidVersionError
from app.helpers import get_version_components
from app.models import *
from attacksurfacemeter.call import Call
from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from attacksurfacemeter.loaders.multigprof_loader import MultigprofLoader


def check_cflow_path(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        if not os.path.exists(value) or os.path.isdir(value):
            raise OptionValueError(
                (
                    'cflow path {0} does not exist or is not a path to a '
                    'file'
                ).format(value)
            )


def check_gprof_path(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        if not os.path.exists(value):
            raise OptionValueError((
                    'gprof path {0} is does not exist'
                ).format(value)
            )


def check_revision(option, opt_str, value, parser, *args, **kwargs):
    setattr(parser.values, option.dest, value)
    if value:
        try:
            (ma, mi, bu) = get_version_components(value)

            if not Revision.objects.filter(number=value).exists():
                raise OptionValueError(
                    'Revision %s does not exist in the database.' % value
                )
        except InvalidVersionError:
            raise OptionValueError(
                'Invalid revision number specified. %s must be formatted as '
                '0.0.0' % opt_str
            )


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option(
            '-s', choices=list(constants.SUBJECTS.keys()), dest='subject',
            help='Name of the subject to load the database with.'
        ),
        make_option(
            '-r', type='str', action='callback', callback=check_revision,
            dest='revision',
            help=(
                'Revision number of the subject to load the database with, '
                'e.g. 2.6.0. Default is None, in which case all revisions of'
                ' the subject are loaded.'
            )
        ),
        make_option(
            '-c', type='str', action='callback', callback=check_cflow_path,
            dest='cflow_path',
            help=(
                'Absolute path to the file containing the cflow call graph.'
            )
        ),
        make_option(
            '-g', type='str', action='callback', callback=check_gprof_path,
            dest='gprof_path',
            help=(
                'Absolute path to a file containing the gprof call graph (or) '
                'the absolute path to a directory in which all files are '
                'assumed to contain gprof call graphs.'
            )
        ),
        make_option(
            '-p', type='int', action='store', dest='num_processes', default=4,
            help=(
                'Number of processes to spawn when executing the command.'
            )
        ),
        make_option(
            '-o', action='store_true', dest='output',
            help=(
                'Enable the creation of file containing the list of all '
                'functions that reach or are reachable from vulnerable '
                'functions within a specified number of hops.'
            )
        ),
        make_option(
            '-t', type='int', action='store', dest='threshold', default=2,
            help=(
                'Number of hops to traverse when identifying ancestors and '
                'descendants of the vulnerable functions.'
            )
        ),
    )
    help = (
        'Loads a set of call graphs (cflow, gprof, or both) and prints '
        'various statistics about the resultant call graph. The Attack '
        'Surface Meter is used to load call graphs.'
    )

    def handle(self, *args, **options):
        stat(**options)


def stat(**options):
    cflow_path = options.get('cflow_path', None)
    gprof_path = options.get('gprof_path', None)
    num_processes = options.get('num_processes')
    output = options.get('output', False)
    threshold = options.get('threshold', None)
    subject = options.get('subject', None)
    revision = options.get('revision', None)
    
    if subject not in settings.ENABLED_SUBJECTS:
        raise CommandError('Subject {0} is not enabled'.format(subject))

    cflow_loader = None
    gprof_loader = None

    cflow_call_graph = None
    gprof_call_graph = None

    begin = datetime.datetime.now()
    if cflow_path:
        fragmentize = False
        if not gprof_path:
            fragmentize = True

        print('Loading cflow call graph')
        cflow_loader = CflowLoader(cflow_path, reverse=True)
        cflow_call_graph = CallGraph.from_loader(cflow_loader, fragmentize)

    if gprof_path:
        fragmentize = False
        if not cflow_path:
            fragmentize = True

        print('Loading gprof call graph')
        if os.path.isdir(gprof_path):
            sources = [
                os.path.join(gprof_path, file_name)
                for file_name in os.listdir(gprof_path)
                if 'txt' in file_name
            ]
            os.environ['DEBUG'] = '1'
            gprof_loader = MultigprofLoader(sources, processes=num_processes)
            gprof_call_graph = CallGraph.from_loader(gprof_loader, fragmentize)
        else:
            gprof_loader = GprofLoader(gprof_path, reverse=False)
            gprof_call_graph = CallGraph.from_loader(gprof_loader, fragmentize)
    end = datetime.datetime.now()

    call_graph = None
    if cflow_call_graph and gprof_call_graph:
        if 'DEBUG' in os.environ:
            print()

        print('Merging cflow and gprof call graphs')
        call_graph = CallGraph.from_merge(
            cflow_call_graph, gprof_call_graph, fragmentize=True
        )
    elif cflow_call_graph:
        call_graph = cflow_call_graph
    elif gprof_call_graph:
        call_graph = gprof_call_graph

    if not call_graph:
        print('Nothing to stat. Exiting.')
        sys.exit(0)

    print('Load completed in {0:.2f} seconds'.format(
        (end - begin).total_seconds()
    ))

    print('#' * 50)
    print('              Call Graph Statistics')
    print('#' * 50)
    print('    Nodes               {0}'.format(len(call_graph.nodes)))
    print('    Edges               {0}'.format(len(call_graph.edges)))
    print('    Entry Points        {0}'.format(len(call_graph.entry_points)))
    print('    Exit Points         {0}'.format(len(call_graph.exit_points)))
    print('    Dangerous           {0}'.format(
        len(nx.get_node_attributes(call_graph.call_graph, 'dangerous'))
    ))
    print('    Monolithicity       {0:4f}'.format(call_graph.monolithicity))
    print('    Fragments           {0}'.format(call_graph.num_fragments))
    print('#' * 50)

    if output:
        generate(
            subject, revision, call_graph, threshold, num_processes
        )


def generate(subject, revision, call_graph, threshold, num_processes):
    print(
        'Generating nodes that reach or are reachable from a vulnerable '
        'function'
    )

    functions = Function.objects.filter(
        revision__number=revision,
        revision__subject__name=subject,
        revision__is_loaded=True,
        is_vulnerable=True
    )

    manager = multiprocessing.Manager()
    queue = manager.Queue(len(functions))

    # Consumer
    consumer = multiprocessing.Process(
        target=process, args=(revision, len(functions), threshold, queue)
    )
    consumer.start()

    # Producers
    with multiprocessing.Pool(num_processes) as pool:
        pool.starmap(
            _generate_,
            [
                (
                    call_graph,
                    Call(function.name, function.file, environment='C'),
                    threshold, queue
                )
                for function in functions
            ]
        )
    consumer.join()


def _generate_(call_graph, function, threshold, queue):
    print(' {0}@{1}'.format(
        function.function_name, function.function_signature
    ))

    reachable = dict()
    for ancestor in nx.ancestors(call_graph.call_graph, function):
        if (
                ancestor not in call_graph.entry_points and
                ancestor not in call_graph.exit_points
           ):

            path_length = nx.shortest_path_length(
                call_graph.call_graph, ancestor, function
            )
            if path_length <= threshold:
                reachable[ancestor] = path_length

    queue.put(
        {
            'function': function,
            'reachable': sorted(
                reachable.items(), key=operator.itemgetter(1)
            ),
        },
        block=True
    )


def process(revision, count, threshold, queue):
    reachables = dict()
    for i in range(1, threshold + 1):
        reachables[i] = set()

    index = 0
    while index < count:
        item = queue.get(block=True)
        index += 1

        reachable = item['reachable']
        for (key, value) in reachable:
            reachables[value].add(key)

    with open('{0}.txt'.format(revision), 'w') as file_:
        for (key, value) in reachables.items():
            file_.write('{0}\n'.format('#' * 30))
            file_.write('Nodes reachable in {0} hop(s)\n'.format(key))
            file_.write('{0}\n'.format('#' * 30))
            for item in value:
                file_.write('  {0}@{1}\n'.format(
                    item.function_name, item.function_signature
                ))
