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
from app.models import Revision, Cve, CveRevision, Function, Reachability


def load_revisions():
    revisions_file = helpers.get_absolute_path(
        'app/assets/data/revisions.csv'
    )

    with transaction.atomic():
        with open(revisions_file, 'r') as _revisions_file:
            reader = csv.reader(_revisions_file)
            for row in reader:
                print('Loading revision {0}'.format(row[1]))
                if not Revision.objects.filter(number=row[1]).exists():
                    revision = Revision()
                    revision.number = (
                        '%d.%d.%d' %
                        helpers.get_version_components(row[1])
                    )
                    revision.type = row[0]
                    revision.ref = row[1]
                    if row[2].strip():
                        revision.configure_options = row[2]
                    revision.save()


def load_cves():
    cve_files = [
        helpers.get_absolute_path('app/assets/data/cves_reported.csv'),
        helpers.get_absolute_path('app/assets/data/cves_non_ffmpeg.csv')
    ]

    with transaction.atomic():
        for cve_file in cve_files:
            with open(cve_file, 'r') as _cve_file:
                reader = csv.reader(_cve_file)
                for row in reader:
                    print('Loading CVE {0}'.format(row[0]))
                    cve = Cve()
                    cve.cve_id = row[0]
                    cve.publish_dt = datetime.datetime.strptime(
                        row[1],
                        '%m/%d/%Y'
                    )
                    cve.save()


def map_cve_to_revision():
    cves_fixed_file = helpers.get_absolute_path(
        'app/assets/data/cves_fixed.csv'
    )

    fixed_cves = dict()
    with open(cves_fixed_file, 'r') as _cves_fixed_file:
        reader = csv.reader(_cves_fixed_file)
        for row in reader:
            if row[1] in fixed_cves:
                fixed_cves[row[1]].append({
                    'revision': row[0], 'commit_hash': row[2]
                })
            else:
                fixed_cves[row[1]] = [{
                    'revision': row[0], 'commit_hash': row[2]
                }]

    with transaction.atomic():
        for cve in Cve.objects.all():
            if cve.cve_id in fixed_cves:
                print('Mapping fix for {0}'.format(cve.cve_id))
                with transaction.atomic():
                    cve.is_fixed = True
                    cve.save()

                    for cve_fix in fixed_cves[cve.cve_id]:
                        print(' to revision {0}'.format(cve_fix['revision']))
                        rev_num = cve_fix['revision']
                        cve_revision = CveRevision()
                        cve_revision.cve = cve
                        cve_revision.revision = Revision.objects.get(
                            number=rev_num, type=constants.RT_TAG
                        )
                        cve_revision.commit_hash = cve_fix['commit_hash']
                        cve_revision.save()


def load(revision, subject_cls):
    debug('Loading {0}'.format(revision.number))
    subject = subject_cls(
        configure_options=revision.configure_options,
        processes=settings.PARALLEL['SUBPROCESSES'],
        git_reference=revision.ref
    )
    subject.initialize()
    subject.prepare()

    # load_function_sloc, load_vulnerable_functions, and load_designed_defenses
    # are independent of one another, so run them in parallel
    function_sloc_thread = threading.Thread(
        target=subject.load_function_sloc,
        name='subject.load_function_sloc'
    )
    vulnerable_functions_thread = threading.Thread(
        target=subject.load_vulnerable_functions,
        name='subject.load_vulnerable_functions',
        args=(get_commit_hashes(revision),)
    )
    designed_defenses_thread = threading.Thread(
        target=subject.load_designed_defenses,
        name='subject.load_designed_defenses'
    )

    function_sloc_thread.start()
    vulnerable_functions_thread.start()
    designed_defenses_thread.start()

    function_sloc_thread.join()
    vulnerable_functions_thread.join()
    designed_defenses_thread.join()

    subject.load_call_graph()

    process(revision, subject)


def process(revision, subject):
    debug('Processing {0}'.format(revision.number))
    vsources = None
    vsinks = None

    manager = multiprocessing.Manager()

    # Shared lists that accumulate the vulnerability source and sink
    #   information when processing each node in the call graph
    vsource = manager.list()
    vsink = manager.list()
    # Shared queue for communication between process_node and save
    queue = manager.Queue(100)

    # Consumer: Spawn a process to save function to the database
    process = multiprocessing.Process(target=_save, args=(subject, queue))
    process.start()

    # Producers: Spawn a pool processes to generate Function objects
    with multiprocessing.Pool(settings.PARALLEL['SUBPROCESSES']) as pool:
        pool.starmap(
            _process,
            [
                (node, attrs, revision, subject, vsource, vsink, queue)
                for (node, attrs) in subject.call_graph.nodes
            ]
        )

        vsources = set(vsource)
        vsinks = set(vsink)

    process.join()

    # TODO: Review hack
    connection.close()

    if vsource or vsinks:
        functions = Function.objects.filter(revision=revision)
        for i in vsources:
            function = functions.get(
                name=i.function_name, file=i.function_signature
            )
            function.is_vulnerability_source = True
            function.save()

        for i in vsinks:
            function = functions.get(
                name=i.function_name, file=i.function_signature
            )
            function.is_vulnerability_sink = True
            function.save()

    revision.monolithicity = subject.call_graph.monolithicity

    revision.num_entry_points = len(subject.call_graph.entry_points)
    revision.num_exit_points = len(subject.call_graph.exit_points)
    revision.num_functions = len(subject.call_graph.nodes)
    revision.num_fragments = subject.call_graph.num_fragments

    revision.is_loaded = True
    revision.save()


def _process(node, attrs, revision, subject, vsource, vsink, queue):
    function = Function()

    function.name = node.function_name
    function.file = node.function_signature
    function.revision = revision
    function.is_entry = node in subject.call_graph.entry_points
    function.is_exit = node in subject.call_graph.exit_points
    function.is_vulnerable = 'vulnerable' in attrs
    function.is_tested = 'tested' in attrs
    function.is_dangerous = 'dangerous' in attrs
    function.is_defense = 'defense' in attrs
    function.sloc = subject.get_function_sloc(
        node.function_name,
        node.function_signature
    )
    function.coupling = subject.call_graph.get_degree(node)
    function.page_rank = subject.call_graph.call_graph.node[node]['page_rank']

    metrics = subject.call_graph.get_entry_surface_metrics(node)
    function.proximity_to_entry = metrics['proximity']
    function.surface_coupling_with_entry = metrics['surface_coupling']
    if function.is_vulnerable and metrics['points']:
        for point in metrics['points']:
            vsource.append(point)

    metrics = subject.call_graph.get_exit_surface_metrics(node)
    function.proximity_to_exit = metrics['proximity']
    function.surface_coupling_with_exit = metrics['surface_coupling']
    if function.is_vulnerable and metrics['points']:
        for point in metrics['points']:
            vsink.append(point)

    # Designed defenses
    metrics = subject.call_graph.get_association_metrics(node, 'defense')
    if metrics:
        function.coupling_with_defense = len(metrics)
        function.proximity_to_defense = stat.mean(metrics.values())

    # Dangerous functions
    metrics = subject.call_graph.get_association_metrics(node, 'dangerous')
    if metrics:
        function.coupling_with_dangerous = len(metrics)
        function.proximity_to_dangerous = stat.mean(metrics.values())

    queue.put((function, node), block=True)


def _save(subject, queue):
    index = 1
    count = len(subject.call_graph.nodes)

    with transaction.atomic():
        while index <= count:
            (function, node) = queue.get(block=True)
            function.save()

            # Compute reachability
            if function.is_entry:
                reachability = Reachability()
                reachability.type = constants.RT_EN
                reachability.function = function
                reachability.value = (
                    subject.call_graph.get_entry_point_reachability(node)
                )
                reachability.save()
            if function.is_exit:
                reachability = Reachability()
                reachability.type = constants.RT_EX
                reachability.function = function
                reachability.value = (
                    subject.call_graph.get_exit_point_reachability(node)
                )
                reachability.save()

            debug(
                'Saving {0:5d}/{1:5d} {2}'.format(index, count, function.name),
                line=True
            )
            index += 1
        print('')


def get_commit_hashes(revision):
    commit_hashes = None
    if revision.type == constants.RT_TAG:
        queryset = CveRevision.objects.filter(revision=revision)
    elif revision.type == constants.RT_BRANCH:
        version_components = helpers.get_version_components(revision.number)
        queryset = CveRevision.objects.filter(
            revision__number__startswith='%d.%d' % (
                version_components[0], version_components[1]
            )
        )

    commit_hashes = [
        item.commit_hash for item in queryset if item.commit_hash != 'NA'
    ]

    return commit_hashes


def profile(revision, subject_cls, index):
    subject = subject_cls(
        configure_options=revision.configure_options,
        processes=settings.PARALLEL['SUBPROCESSES'],
        git_reference=revision.ref
    )
    subject.gprof(index)


def debug(message, line=False):
    if 'DEBUG' in os.environ:
        if line:
            sys.stdout.write('\r')
            sys.stdout.write('\033[K')
            sys.stdout.write('[DEBUG] {0}'.format(message))
            sys.stdout.flush()
        else:
            print('[DEBUG] {0}'.format(message))
