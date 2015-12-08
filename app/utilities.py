import datetime
import csv
import multiprocessing
import os
import statistics as stat
import sys
import threading

import numpy as np

from queue import Queue

from django.conf import settings
from django.db import connection, transaction
from scipy import stats

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

    analyze(subject, were_vuln, become_vuln, processes)
    analyze_sensitivity(subject, become_vuln, processes)

    end = datetime.datetime.now()
    debug('Loading {0} completed in {1:.2f} minutes'.format(
        release, ((end - begin).total_seconds() / 60)
    ))


def analyze(subject, were_vuln, become_vuln, processes):
    debug('Processing {0}'.format(subject.release))

    manager = multiprocessing.Manager()

    # Shared queue for communication between _analyze and _save
    queue = manager.Queue(500)

    # Consumer: Spawn a process to save function to the database
    process = multiprocessing.Process(
            target=_save, args=(Function, len(subject.call_graph.nodes), queue)
        )
    process.start()

    # Producers: Spawn a pool processes to generate Function objects
    with multiprocessing.Pool(processes) as pool:
        pool.starmap(
            _analyze,
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


def _analyze(node, attrs, subject, were_vuln, become_vuln, queue):
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


def analyze_sensitivity(subject, become_vuln, processes):
    debug('Performing sensitivity analysis on {0}'.format(subject.release))

    # List of dictionaries each containing a set of values for damping,
    # personalization dictionary, and edge weights
    parameter_set = list()

    # TODO: Implement varying weights
    weights = {
            'base': {'call': 100, 'return': 50},
            'dangerous': 25,'defense': -25,'tested': -25,'vulnerable': 25
        }
    # Damping factor from 10% to 90% with 5% increments
    for damping in np.arange(0.1, 1.0, 0.05):
        # Personalization from 1 to 1000000 increasing exponentially
        for power in range(0, 7):
            entry = 10 ** power
            for power in range(0, 7):
                exit = 10 ** power

                parameter_set.append(
                        {
                            'damping': round(damping, 2),
                            'personalization': {
                                'entry': entry, 'exit': exit, 'other': 1
                            },
                            'weights': weights
                        }
                    )

    manager = multiprocessing.Manager()

    # Shared queue for communication between _analyze and _save_functions
    queue = manager.Queue(500)

    # Consumer: Spawn a process to save function to the database
    process = multiprocessing.Process(
            target=_save, args=(Sensitivity, len(parameter_set), queue)
        )
    process.start()

    # Producers: Spawn a pool processes to generate Sensitivity objects
    with multiprocessing.Pool(processes) as pool:
        pool.starmap(
            _analyze_sensitivity,
            [
                (subject, become_vuln, parameters, queue)
                for parameters in parameter_set
            ],
            chunksize=1
        )

    process.join()


def _analyze_sensitivity(subject, become_vuln, parameters, queue):
    subject.call_graph.assign_weights(parameters['weights'])
    page_rank = subject.call_graph.get_page_rank(
            damping=parameters['damping'],
            entry=parameters['personalization']['entry'],
            exit=parameters['personalization']['exit'],
            other=parameters['personalization']['other'],
        )
    
    treatment = list()
    control = list()
    for (key, value) in page_rank.items():
        if key in become_vuln:
            treatment.append(value)
        else:
            control.append(value)

    (_, p) = stats.ranksums(np.array(treatment), np.array(control))

    sensitivity = Sensitivity()

    sensitivity.release = subject.release
    sensitivity.damping = parameters['damping']

    sensitivity.personalization_entry = parameters['personalization']['entry']
    sensitivity.personalization_exit = parameters['personalization']['exit']
    sensitivity.personalization_other = parameters['personalization']['other']

    sensitivity.weight_call = parameters['weights']['base']['call']
    sensitivity.weight_return = parameters['weights']['base']['return']
    sensitivity.weight_dangerous = parameters['weights']['dangerous']
    sensitivity.weight_defense = parameters['weights']['defense']
    sensitivity.weight_tested = parameters['weights']['tested']
    sensitivity.weight_vulnerable = parameters['weights']['vulnerable']

    sensitivity.p = p
    # TODO: Compute Cohen's d
    sensitivity.d = 0

    queue.put(sensitivity, block=True)


def _save(model, count, queue):
    index = 1

    size = 50
    instances = list()
    with transaction.atomic():
        while index <= count:
            instance = queue.get(block=True)

            instance_str = str(instance)
            instance_str = instance_str[:50] + (instance_str[50:] and '...')
            debug('{0}/{1} {2}'.format(index, count, instance_str), line=True)

            instances.append(instance)
            if (index % size) == 0:
                debug('Inserting {0} instances.'.format(size), line=True)
                model.objects.bulk_create(instances, batch_size=size)
                instances.clear()

            index += 1

        if instances:
            debug(
                    'Inserting the last {0} instances.'.format(len(instances)),
                    line=True
                )
            model.objects.bulk_create(instances)


def debug(message, line=False):
    if 'DEBUG' in os.environ:
        if line:
            sys.stdout.write('\r\033[K')
            sys.stdout.write('[DEBUG] {0}'.format(message))
            sys.stdout.flush()
        else:
            print('[DEBUG] {0}'.format(message))
