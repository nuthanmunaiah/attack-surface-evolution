import datetime
import os
import sys
import shutil

from optparse import make_option, OptionValueError

import networkx as nx

from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from attacksurfacemeter.loaders.multigprof_loader import MultigprofLoader
from django.core.management.base import BaseCommand


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


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
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
                'Number of processes to spawn when loading multiple gprof '
                'files'
            )
        ),
    )
    help = (
        'Loads a set of call graphs (cflow, gprof, or both) and prints '
        'various statistics about the resultant call graph. The Attack '
        'Surface Meter is used to load call graphs.'
    )

    def handle(self, *args, **options):
        cflow_path = options.get('cflow_path', None)
        gprof_path = options.get('gprof_path', None)
        num_processes = options.get('num_processes')

        stat(cflow_path, gprof_path, num_processes)


def stat(cflow_path, gprof_path, num_processes):
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
