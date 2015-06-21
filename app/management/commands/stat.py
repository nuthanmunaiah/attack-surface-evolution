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
                'Absolute path to a file containing the gprof call graph. '
                'If the path is to a directory all text files in the directory'
                'are treated as containing gprof call graphs'
            )
        ),
        make_option(
            '-o', action='store_true', dest='is_output_enabled',
            help=(
                'When enabled, output files are created at the user\'s home '
                'directory.'
            )
        ),
        make_option(
            '-p', type='int', action='store', dest='num_processes', default=1,
            help=(
                'Number of processes to spawn when loading multiple gprof files'
            )
        ),
    )
    help = (
        'Prints various statistics about an set of call graphs. The  Attack '
        'Surface Meter is used to load call graphs.'
    )

    def handle(self, *args, **options):
        is_output_enabled = options.get('is_output_enabled', False)
        cflow_path = options.get('cflow_path', None)
        gprof_path = options.get('gprof_path', None)
        num_processes = options.get('num_processes', 1)

        stat(cflow_path, gprof_path, is_output_enabled, num_processes)


def stat(cflow_path, gprof_path, is_output_enabled, num_processes):
    cflow_loader = None
    gprof_loader = None

    cflow_call_graph = None
    gprof_call_graph = None

    begin = datetime.datetime.now()
    if cflow_path:
        print('Loading cflow call graph')
        cflow_loader = CflowLoader(cflow_path, reverse=True)
        cflow_call_graph = CallGraph.from_loader(cflow_loader)
    
    if gprof_path:
        print('Loading gprof call graph')
        if os.path.isdir(gprof_path):
            sources = [
                os.path.join(gprof_path, file_name)
                for file_name in os.listdir(gprof_path)
                if 'txt' in file_name
            ]
            os.environ['DEBUG'] = '1'
            gprof_loader = MultigprofLoader(sources, processes=num_processes)
            gprof_call_graph = CallGraph.from_loader(gprof_loader)
        else:
            gprof_loader = GprofLoader(gprof_path, reverse=False)
            gprof_call_graph = CallGraph.from_loader(gprof_loader)
    end = datetime.datetime.now()

    call_graph = None
    if cflow_call_graph and gprof_call_graph:
        print('Merging cflow and gprof call graphs')
        call_graph = CallGraph.from_merge(cflow_call_graph, gprof_call_graph)
        if 'DEBUG' in os.environ:
            print()
    elif cflow_call_graph:
        call_graph = cflow_call_graph
    elif gprof_call_graph:
        call_graph = gprof_call_graph

    if not call_graph:
        print('Nothing to stat. Exiting.')
        sys.exit(0)

    print('Load completed in {0:.2f} seconds.'.format(
        (end - begin).total_seconds()
    ))
    call_graph.remove_standard_library_calls()

    uncalled_functions = [
        k for (k, v) in nx.degree(call_graph.call_graph).items() if v == 0
    ]

    undirected_call_graph = call_graph.call_graph.to_undirected()
    connected_components = list(
        nx.connected_component_subgraphs(undirected_call_graph)
    )

    print('')
    print('#' * 30)
    print('  Call Graph Statistics')    
    print('#' * 30)
    print('    Nodes            {0}'.format(len(call_graph.nodes)))
    print('    Edges            {0}'.format(len(call_graph.edges)))
    print('    Components       {0}'.format(len(connected_components)))
    print('    0-degree Nodes   {0}'.format(len(uncalled_functions)))
    print('#' * 30)

    if is_output_enabled:
        create_output_files(connected_components, uncalled_functions)


def create_output_files(components, functions):
    root = os.path.expanduser('~/.stat')
    if not os.path.exists(root):
        os.mkdir(root)
        print('Output path {0} created'.format(root))
    else:
        print('Using existing Output path {0}'.format(root))
        if len(os.listdir(root)) != 0:
            print(
                (
                    '[WARNING] {0} is not empty. Exising files will be deleted.'
                ).format(root)
            )
        shutil.rmtree(root)
        os.mkdir(root)

    file_path = os.path.join(root, 'uncalled.csv')
    with open(file_path, 'w+') as file_:
        for function in functions:
            file_.write('{0},{1}\n'.format(
                function.function_name, function.function_signature
            ))
    print('The list of uncalled functions written to {0}'.format(file_path))

    node_threshold = 9
    file_path = os.path.join(root, 'components.txt')
    with open(file_path, 'w+') as file_:
        file_.write('{0} {1} {2}\n'.format('Index', 'Nodes', 'Edges'))
        for index, component in enumerate(components):
            file_.write('{0:5d} {1:5d} {2:5d}\n'.format(
                (index + 1), len(component.nodes()), len(component.edges())
            ))
            if len(component.nodes()) > node_threshold:
                nx.write_dot(
                    component,
                    os.path.join(root, '{0}.dot'.format(index + 1))
                )
    print('The statistics of components written to {0}'.format(file_path))
    print(
        (
            'Dot file of components containing more than {0} nodes written to '
            '{1}'
        ).format(node_threshold, root)
    )

