import datetime
import csv
import multiprocessing
import os
import statistics as stat
import sys
import threading

import numpy
import scipy.stats

import app.stats

from queue import Queue

from django.conf import settings
from django.db import connection, transaction

from app import constants
from app.helpers import debug
from app.models import *
from attacksurfacemeter.call import Call
from attacksurfacemeter.environments import Environments


def load(subject, processes):
    begin = datetime.datetime.now()

    debug('Loading {0}'.format(subject.release))
    subject.prepare(processes)
    subject.load_call_graph(processes)
    subject.call_graph.assign_weights()
    subject.call_graph.assign_page_rank(name='page_rank')

    _load(subject, processes)

    end = datetime.datetime.now()
    debug('Loading {0} completed in {1:.2f} minutes'.format(
        subject.release, ((end - begin).total_seconds() / 60)
    ))


def _load(subject, processes):
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
                (node, attrs, subject, queue)
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


def _analyze(node, attrs, subject, queue):
    function = Function()

    function.name = node.function_name
    function.file = node.function_signature
    function.release = subject.release
    function.is_entry = node in subject.call_graph.entry_points
    function.is_exit = node in subject.call_graph.exit_points
    function.was_vulnerable = node in subject.were_vuln
    function.becomes_vulnerable = node in subject.become_vuln
    function.is_tested = 'tested' in attrs
    function.calls_dangerous = 'dangerous' in attrs
    function.is_defense = 'defense' in attrs

    sloc = subject.get_function_sloc(
            node.function_name,
            node.function_signature
        )
    if sloc is not None:
        function.sloc = sloc[2]
        if not function.file:
            debug('Guessing file information for {0}'.format(function.name))
            function.file = sloc[1]

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


def analyze_sensitivity(subject, parameters):
    debug('Performing sensitivity analysis on {0}'.format(subject.release))

    subject.load_call_graph()

    # A dictionary the set of values for damping, personalization dictionary,
    # and edge weights
    parameters = {
            'damping': parameters[0],
            'personalization': {
                'entry': parameters[1],
                'exit': parameters[2],
                'other': parameters[3]
            },
            'weights': {
                'base': {'call': parameters[4], 'return': parameters[5]},
                'dangerous': parameters[6],
                'vulnerable': parameters[7]
            }
        }

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
        if key in subject.become_vuln:
            treatment.append(value)
        else:
            control.append(value)

    treatment = numpy.array(treatment)
    control = numpy.array(control)

    (_, p) = scipy.stats.ranksums(treatment, control)

    sensitivity = Sensitivity()

    sensitivity.release = subject.release
    sensitivity.damping = parameters['damping']

    sensitivity.personalization_entry = parameters['personalization']['entry']
    sensitivity.personalization_exit = parameters['personalization']['exit']
    sensitivity.personalization_other = parameters['personalization']['other']

    sensitivity.weight_call = parameters['weights']['base']['call']
    sensitivity.weight_return = parameters['weights']['base']['return']
    sensitivity.weight_dangerous = parameters['weights'].get('dangerous', 0)
    sensitivity.weight_defense = parameters['weights'].get('defense', 0)
    sensitivity.weight_tested = parameters['weights'].get('tested', 0)
    sensitivity.weight_vulnerable = parameters['weights'].get('vulnerable', 0)

    sensitivity.p = p
    sensitivity.d = app.stats.cohensd(treatment, control)

    sensitivity.save()


def update_pagerank(subject):
    begin = datetime.datetime.now()

    debug('Updating {0}'.format(subject.release))
    subject.load_call_graph()

    # TODO: Initialize the parameters dictionary before executing this method
    parameters = {
            'damping': 1.0,
            'personalization': {
                'entry': 1,
                'exit': 1,
                'other': 1
            },
            'weights': {
                'base': {'call': 1, 'return': 1},
                'dangerous': 1,
                'vulnerable': 1
            }
        }

    subject.call_graph.assign_weights(parameters['weights'])
    subject.call_graph.assign_page_rank(
            name='page_rank',
            damping=parameters['damping'],
            entry=parameters['personalization']['entry'],
            exit=parameters['personalization']['exit'],
            other=parameters['personalization']['other'],
        )

    count = 0
    functions = Function.objects.filter(release=subject.release)
    for (node, attrs) in subject.call_graph.nodes:
        function = None

        _function = functions.filter(name=node.function_name)
        if _function.count() == 1:
            function = functions.get(name=node.function_name)
        else:
            _function = functions.filter(
                    name=node.function_name, file=node.function_signature
                )
            if _function.exists():
                function = functions.get(
                        name=node.function_name, file=node.function_signature
                    )

        if function is not None:
            count += 1

            function.page_rank = attrs['page_rank']
            function.save()
        else:
            debug('{0}@{1} not found'.format(
                    node.function_name, node.function_signature
                ))

    end = datetime.datetime.now()
    debug('Updated {0} records'.format(count))
    debug('Updating {0} completed in {1:.2f} minutes'.format(
        subject.release, ((end - begin).total_seconds() / 60)
    ))


def update_sloc(subject):
    begin = datetime.datetime.now()

    debug('Updating SLOC {0}'.format(subject.release))
    subject.prepare()

    count = 0
    functions = Function.objects.filter(release=subject.release)
    for function in functions:
        sloc = subject.get_function_sloc(function.name, function.file)
        if sloc is not None:
            function.sloc = sloc[2]
            if not function.file:
                debug(
                    'Guessing file information for {0}'.format(function.name)
                )
                function.file = sloc[1]
            function.save()
            count += 1

    end = datetime.datetime.now()
    debug('Updated {0} records'.format(count))
    debug('Updating {0} completed in {1:.2f} minutes'.format(
        subject.release, ((end - begin).total_seconds() / 60)
    ))


def _save(model, count, queue):
    index = 1

    size = settings.DATABASES['default']['BULK']
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
