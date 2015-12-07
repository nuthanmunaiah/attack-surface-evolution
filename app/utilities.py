import datetime
import csv
import multiprocessing
import os
import statistics as stat
import sys
import threading

from queue import Queue

from django.conf import settings
from django.db import connection, transaction

from app import constants, helpers
from app.models import *
from attacksurfacemeter.call import Call
from attacksurfacemeter.environments import Environments


def load(release, subject, processes):
    begin = datetime.datetime.now()

    debug('Loading {0}'.format(release))
    subject.prepare(release, processes)

    fixes = VulnerabilityFix.objects.filter(
            cve_release__cve__subject=release.subject
        )
    were_vuln = list()
    become_vuln = list()
    for _release in Release.objects.filter(subject=release.subject):
        if _release <= release:
            were_vuln += [
                    Call(fix.name, fix.file, Environments.C)
                    for fix in fixes.filter(cve_release__release=_release)
                ]
        else:
            become_vuln += [
                    Call(fix.name, fix.file, Environments.C)
                    for fix in fixes.filter(cve_release__release=_release)
                ]
    subject.load_call_graph(were_vuln, processes)

    process(subject, were_vuln, become_vuln, processes)

    end = datetime.datetime.now()
    debug('Loading {0} completed in {1:.2f} minutes'.format(
        release, ((end - begin).total_seconds() / 60)
    ))


def process(subject, were_vuln, become_vuln, processes):
    debug('Processing {0}'.format(subject.release))

    manager = multiprocessing.Manager()

    # Shared queue for communication between process_node and save
    queue = manager.Queue(500)

    # Consumer: Spawn a process to save function to the database
    process = multiprocessing.Process(target=_save, args=(subject, queue))
    process.start()

    # Producers: Spawn a pool processes to generate Function objects
    with multiprocessing.Pool(processes) as pool:
        pool.starmap(
            _process,
            [
                (node, attrs, subject, were_vuln, become_vuln, queue)
                for (node, attrs) in subject.call_graph.nodes
            ],
            chunksize=1
        )

    process.join()

    # TODO: Review hack
    connection.close()

    release = subject.release

    release.monolithicity = subject.call_graph.monolithicity

    release.num_entry_points = len(subject.call_graph.entry_points)
    release.num_exit_points = len(subject.call_graph.exit_points)
    release.num_functions = len(subject.call_graph.nodes)
    release.num_fragments = subject.call_graph.num_fragments

    release.is_loaded = True
    release.save()


def _process(node, attrs, subject, were_vuln, become_vuln, queue):
    function = Function()

    function.name = node.function_name
    function.file = node.function_signature
    function.release = subject.release
    function.is_entry = node in subject.call_graph.entry_points
    function.is_exit = node in subject.call_graph.exit_points
    function.was_vulnerable = node in were_vuln
    function.becomes_vulnerable = node in become_vuln
    function.is_tested = 'tested' in attrs
    function.calls_dangerous = 'dangerous' in attrs
    function.is_defense = 'defense' in attrs
    function.sloc = subject.get_function_sloc(
        node.function_name,
        node.function_signature
    )
    (function.fan_in, function.fan_out) = subject.call_graph.get_fan(node)

    function.page_rank = attrs['page_rank']
    function.page_rank_b = attrs['page_rank_b']
    function.page_rank_bv = attrs['page_rank_bv']
    function.page_rank_bvt = attrs['page_rank_bvt']
    function.page_rank_bvtda = attrs['page_rank_bvtda']
    function.page_rank_bvtde = attrs['page_rank_bvtde']
    function.page_rank_bvda = attrs['page_rank_bvda']
    function.page_rank_bvdade = attrs['page_rank_bvdade']
    function.page_rank_bvde = attrs['page_rank_bvde']
    function.page_rank_bt = attrs['page_rank_bt']
    function.page_rank_btda = attrs['page_rank_btda']
    function.page_rank_btdade = attrs['page_rank_tdade']
    function.page_rank_btde = attrs['page_rank_btde']
    function.page_rank_bda = attrs['page_rank_bda']
    function.page_rank_bde = attrs['page_rank_bde']
    function.page_rank_bdade = attrs['page_rank_bdade']

    # Entry points
    metrics = subject.call_graph.get_shortest_path_length(node, 'entry')
    if metrics is not None:
        function.proximity_to_entry = (
            stat.mean(metrics.values()) if metrics else 0.0
        )

    # Exit points
    metrics = subject.call_graph.get_shortest_path_length(node, 'exit')
    if metrics is not None:
        function.proximity_to_exit = (
            stat.mean(metrics.values()) if metrics else 0.0
        )

    # Designed defenses
    metrics = subject.call_graph.get_shortest_path_length(node, 'defense')
    if metrics is not None:
        function.proximity_to_defense = (
            stat.mean(metrics.values()) if metrics else 0.0
        )

    # Dangerous functions
    metrics = subject.call_graph.get_shortest_path_length(node, 'dangerous')
    if metrics is not None:
        function.proximity_to_dangerous = (
            stat.mean(metrics.values()) if metrics else 0.0
        )

    queue.put(function, block=True)


def _save(subject, queue):
    index = 1
    count = len(subject.call_graph.nodes)

    size = 500
    functions = list()
    with transaction.atomic():
        while index <= count:
            function = queue.get(block=True)
            debug(
                'Saving {0:5d}/{1:5d} {2}'.format(
                    index, count,
                    function.name[:50] + (function.name[50:] and '...')
                ),
                line=True
            )
            functions.append(function)
            if (index % size) == 0:
                print('')
                debug(
                    'Inserting {0} functions into the database.'.format(
                        size
                    )
                )
                Function.objects.bulk_create(functions, batch_size=size)
                functions.clear()

            index += 1

        print('')
        if functions:
            debug(
                'Inserting the last {0} functions into the database.'.format(
                    len(functions)
                )
            )
            Function.objects.bulk_create(functions)
            functions.clear()


def profile(release, subject, index):
    subject.initialize(release)
    subject.gprof(index)


def debug(message, line=False):
    if 'DEBUG' in os.environ:
        if line:
            sys.stdout.write('\r\033[K')
            sys.stdout.write('[DEBUG] {0}'.format(message))
            sys.stdout.flush()
        else:
            print('[DEBUG] {0}'.format(message))
