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
from app.models import Subject, Revision, Cve, CveRevision, Function


def load_subjects():
    for item in settings.SUBJECTS:
        print('Loading subject {0}'.format(item))
        subject = Subject()
        subject.name = item
        subject.save()


def load_revisions():
    for item in settings.SUBJECTS:
        subject = Subject.objects.get(name=item)
        revisions_file = helpers.get_absolute_path(
            'app/assets/data/{0}/revisions.csv'.format(subject.name)
        )
        with open(revisions_file, 'r') as _revisions_file:
            reader = csv.reader(_revisions_file)
            for row in reader:
                print('Loading revision {0} of {1}'.format(
                    row[1], subject.name)
                )
                revision = Revision()
                revision.subject = subject
                revision.type = row[0]
                revision.number = (
                    '%d.%d.%d' %
                    helpers.get_version_components(row[1])
                )
                revision.ref = row[1]
                revision.configure_options = row[2]
                revision.save()


def load_cves():
    for item in settings.SUBJECTS:
        subject = Subject.objects.get(name=item)
        cves_file = helpers.get_absolute_path(
            'app/assets/data/{0}/cves.csv'.format(subject.name)
        )
        with open(cves_file, 'r') as _cve_file:
            reader = csv.reader(_cve_file)
            for row in reader:
                print('Loading CVE {0} of {1}'.format(
                    row[0], subject.name
                ))
                cve = Cve()
                cve.subject = subject
                cve.cve_id = row[0]
                cve.publish_dt = datetime.datetime.strptime(
                    row[1], '%m/%d/%Y'
                )
                cve.save()


def map_cve_to_revision():
    for item in settings.SUBJECTS:
        subject = Subject.objects.get(name=item)
        cves_fixed_file = helpers.get_absolute_path(
            'app/assets/data/{0}/cves_fixed.csv'.format(subject.name)
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

        for cve in Cve.objects.filter(subject=subject):
            if cve.cve_id in fixed_cves:
                print('Mapping fix for {0} of {1}'.format(
                    cve.cve_id, subject.name
                ))
                with transaction.atomic():
                    cve.is_fixed = True
                    cve.save()

                    for cve_fix in fixed_cves[cve.cve_id]:
                        print(' to revision {0}'.format(
                            cve_fix['revision']
                        ))
                        rev_num = cve_fix['revision']
                        cve_revision = CveRevision()
                        cve_revision.cve = cve
                        cve_revision.revision = Revision.objects.get(
                            subject=subject, number=rev_num,
                            type=constants.RT_TAG
                        )
                        cve_revision.commit_hash = cve_fix['commit_hash']
                        cve_revision.save()


def load(revision, subject_cls):
    begin = datetime.datetime.now()

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

    end = datetime.datetime.now()
    debug('Loading {0} completed in {1:.2f} minutes'.format(
        revision.number, ((end - begin).total_seconds() / 60)
    ))


def process(revision, subject):
    debug('Processing {0}'.format(revision.number))

    manager = multiprocessing.Manager()

    # Shared queue for communication between process_node and save
    queue = manager.Queue(200)

    # Consumer: Spawn a process to save function to the database
    process = multiprocessing.Process(target=_save, args=(subject, queue))
    process.start()

    # Producers: Spawn a pool processes to generate Function objects
    with multiprocessing.Pool(settings.PARALLEL['SUBPROCESSES']) as pool:
        pool.starmap(
            _process,
            [
                (node, attrs, revision, subject, queue)
                for (node, attrs) in subject.call_graph.nodes
            ],
            chunksize=1
        )

    process.join()

    # TODO: Review hack
    connection.close()

    revision.monolithicity = subject.call_graph.monolithicity

    revision.num_entry_points = len(subject.call_graph.entry_points)
    revision.num_exit_points = len(subject.call_graph.exit_points)
    revision.num_functions = len(subject.call_graph.nodes)
    revision.num_fragments = subject.call_graph.num_fragments

    revision.is_loaded = True
    revision.save()


def _process(node, attrs, revision, subject, queue):
    function = Function()

    function.name = node.function_name
    function.file = node.function_signature
    function.revision = revision
    function.is_entry = node in subject.call_graph.entry_points
    function.is_exit = node in subject.call_graph.exit_points
    function.is_vulnerable = 'vulnerable' in attrs
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

    queue.put((function, node), block=True)


def _save(subject, queue):
    index = 1
    count = len(subject.call_graph.nodes)

    size = 999
    functions = list()
    with transaction.atomic():
        while index <= count:
            (function, node) = queue.get(block=True)
            debug(
                'Saving {0:5d}/{1:5d} {2}'.format(
                    index, count,
                    function.name[:50] + (function.name[50:] and '...')
                ),
                line=True
            )
            functions.append(function)
            if (index % 999) == 0:
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
            sys.stdout.write('\r\033[K')
            sys.stdout.write('[DEBUG] {0}'.format(message))
            sys.stdout.flush()
        else:
            print('[DEBUG] {0}'.format(message))
