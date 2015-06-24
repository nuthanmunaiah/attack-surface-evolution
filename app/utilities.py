import datetime
import csv
import os
import threading

from queue import Queue

from django.conf import settings
from django.db import connection, transaction
from joblib import Parallel, delayed

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
    # TODO: Revisit call to connection.close()
    connection.close()

    subject = subject_cls(
        configure_options=revisions.configure_options,
        processes=settings.PARALLEL['SUBPROCESSES'],
        git_reference=revision.ref
    )
    subject.initialize()
    subject.prepare()

    # load_call_graph, load_vulnerable_functions, and load_function_sloc are
    #   independent of one another, so run them in parallel
    call_graph_thread = threading.Thread(
        target=subject.load_call_graph,
        name='subject.load_call_graph'
    )
    vulnerable_functions_thread = threading.Thread(
        target=subject.load_vulnerable_functions,
        name='subject.load_vulnerable_functions',
        args=(get_commit_hashes(revision),)
    )
    function_sloc_thread = threading.Thread(
        target=subject.load_function_sloc,
        name='subject.load_function_sloc'
    )

    call_graph_thread.start()
    vulnerable_functions_thread.start()
    function_sloc_thread.start()

    call_graph_thread.join()
    vulnerable_functions_thread.join()
    function_sloc_thread.join()

    process_revision(revision, subject)


def process_revision(revision, subject):
    vulnerability_source = set()
    vulnerability_sink = set()

    with transaction.atomic():
        # TODO: Evaluate the Global Interpreter Lock (GIL) phenemenon
        results = Parallel(
            n_jobs=settings.PARALLEL['THREADS'],
            backend='threading'
        )(
            delayed(process_node)(node, revision, subject)
            for node in subject.call_graph.nodes
        )

        for (node, function, vsource, vsink) in results:
            function.save()

            reachability = None
            if function.is_entry:
                reachability = get_reachability(
                    node, function, constants.RT_EN, subject
                )
            elif function.is_exit:
                reachability = get_reachability(
                    node, function, constants.RT_EX, subject
                )

            if reachability:
                reachability.save()

            for item in vsource:
                vulnerability_source.add(item)

            for item in vsink:
                vulnerability_sink.add(item)

        revision.num_entry_points = len(subject.call_graph.entry_points)
        revision.num_exit_points = len(subject.call_graph.exit_points)
        revision.num_functions = len(subject.call_graph.nodes)
        revision.num_attack_surface_functions = len(
            subject.call_graph.attack_surface_graph_nodes
        )
        revision.is_loaded = True
        revision.save()

        for item in vulnerability_source:
            function = Function.objects.get(
                revision=revision, name=item.function_name,
                file=item.function_signature
            )
            function.is_vulnerability_source = True
            function.save()

        for item in vulnerability_sink:
            function = Function.objects.get(
                revision=revision, name=item.function_name,
                file=item.function_signature
            )
            function.is_vulnerability_sink = True
            function.save()


def process_node(node, revision, subject):
    vsource = set()
    vsink = set()

    function = Function()

    function.name = node.function_name
    function.file = node.function_signature
    function.revision = revision
    function.is_entry = node in subject.call_graph.entry_points
    function.is_exit = node in subject.call_graph.exit_points
    function.is_vulnerable = subject.is_function_vulnerable(
        node.function_name,
        node.function_signature
    )
    function.is_tested = subject.call_graph.call_graph.node[node][
        'tested'
    ]
    function.sloc = subject.get_function_sloc(
        node.function_name,
        node.function_signature
    )
    function.coupling = subject.call_graph.get_degree(node)
    function.page_rank_10000_1_hl = subject.call_graph.call_graph.node[node][
        'page_rank_10000_1_hl'
    ]
    function.page_rank_100_1_hl = subject.call_graph.call_graph.node[node][
        'page_rank_100_1_hl'
    ]
    function.page_rank_10000_1_lh = subject.call_graph.call_graph.node[node][
        'page_rank_10000_1_lh'
    ]
    function.page_rank_100_1_lh = subject.call_graph.call_graph.node[node][
        'page_rank_100_1_lh'
    ]

    if node in subject.call_graph.attack_surface_graph_nodes:
        function.is_connected_to_attack_surface = True

        metrics = subject.call_graph.get_entry_surface_metrics(node)
        function.proximity_to_entry = metrics['proximity']
        function.surface_coupling_with_entry = metrics['surface_coupling']

        if function.is_vulnerable and metrics['points']:
            for point in metrics['points']:
                vsource.add(point)

        metrics = subject.call_graph.get_exit_surface_metrics(node)
        function.proximity_to_exit = metrics['proximity']
        function.surface_coupling_with_exit = metrics['surface_coupling']

        if function.is_vulnerable and metrics['points']:
            for point in metrics['points']:
                vsink.add(point)

    # TODO: Review returning node
    return (node, function, vsource, vsink)


def get_reachability(node, function, type_, subject):
    reachability = Reachability()
    reachability.type = type_
    reachability.function = function
    if type_ == constants.RT_EN:
        reachability.value = subject.call_graph.get_entry_point_reachability(
            node
        )
    elif type_ == constants.RT_EX:
        reachability.value = subject.call_graph.get_exit_point_reachability(
            node
        )

    return reachability


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
        num_jobs=settings.PARALLEL['THREADS'], git_reference=revision.ref
    )
    subject.gprof(index)
