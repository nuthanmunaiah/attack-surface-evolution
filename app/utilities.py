import datetime
import csv
import os
import threading

from queue import Queue

from django.conf import settings
from django.db import connection, transaction

from app import constants, helpers
from app.models import Revision, Cve, CveRevision, Function

def load_revisions():
	revisions_file = helpers.get_absolute_path(
		'app/assets/data/revisions.csv'
	)

	with transaction.atomic():
		with open(revisions_file, 'r') as _revisions_file:
			reader = csv.reader(_revisions_file)
			for row in reader:
				if not Revision.objects.filter(number=row[0]).exists():
					revision = Revision()
					revision.number = ('%d.%d.%d' % 
						helpers.get_version_components(row[1]))
					revision.type = row[0]
					revision.ref = row[1]
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
					cve = Cve()
					cve.cve_id = row[0]
					cve.publish_dt = datetime.datetime.strptime(row[1],
						'%m/%d/%Y')
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
				with transaction.atomic():
					cve.is_fixed = True
					cve.save()

					for cve_fix in fixed_cves[cve.cve_id]:
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

	subject = subject_cls(settings.PARALLEL['JOBS'], revision.ref)
	subject.prepare()
	
	# load_call_graph, load_vulnerable_functions, and load_function_sloc are 
	# 	independent of one another, so run them in parallel
	call_graph_thread = threading.Thread(
		target=subject.load_call_graph, 
		name='subject.load_call_graph'
	)
	vulnerable_functions_thread = threading.Thread(
		target=subject.load_vulnerable_functions, 
		name='subject.load_vulnerable_functions', 
		args=(list(CveRevision.objects.filter(revision=revision)),)
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
		# Process entry points
		for node in subject.call_graph.entry_points:
			function = process_node(node, revision, subject)

			r = Reachability()
			r.type = constants.RT_EN
			r.function = function
			r.value = subject.call_graph.get_entry_point_reachability(node)
			r.save()

			function.save()

		# Process exit points
		for node in subject.call_graph.entry_points:
			function = process_node(node, revision, subject)

			expr = Reachability()
			expr.type = constants.RT_EX
			expr.function = function
			expr.value = subject.call_graph.get_exit_point_reachability(node)
			expr.save()

			function.save()

		# Process all other nodes
		for node in subject.call_graph.nodes:
			function = process_node(node, revision, subject)
			function.save()
			
		revision.num_entry_points = len(subject.call_graph.entry_points)
		revision.num_exit_points = len(subject.call_graph.exit_points)
		revision.num_functions = len(subject.call_graph.nodes)
		revision.num_attack_surface_functions = len(
			subject.call_graph.attack_surface_graph_nodes
		)
		revision.is_loaded = True
		revision.save()

		for item in vulnerability_source:
			function = Function.objects.get(revision=revision, 
				name=item.function_name, file=item.function_signature)
			function.is_vulnerability_source = True
			function.save()

		for item in vulnerability_sink:
			function = Function.objects.get(revision=revision, 
				name=item.function_name, file=item.function_signature)
			function.is_vulnerability_sink = True
			function.save()

def process_node(node, revision, subject):
	function = Function()

	function.revision = revision
	function.name = node.function_name
	function.file = node.function_signature
	function.is_entry = node in subject.call_graph.entry_points
	function.is_exit = node in subject.call_graph.exit_points
	function.is_vulnerable = subject.is_function_vulnerable(node.function_name,
		node.function_signature)
	function.sloc = subject.get_function_sloc(node.function_name, 
		node.function_signature)

	if node in subject.call_graph.attack_surface_graph_nodes:
		function.is_connected_to_attack_surface = True

		metrics = subject.call_graph.get_entry_surface_metrics(node)
		function.proximity_to_entry = metrics['proximity']
		function.surface_coupling_with_entry = metrics['surface_coupling']

		if function.is_vulnerable and metrics['points']:
			for point in metrics['points']:
				vulnerability_source.add(point)

		metrics = subject.call_graph.get_exit_surface_metrics(node)
		function.proximity_to_exit = metrics['proximity']
		function.surface_coupling_with_exit = metrics['surface_coupling']

		if function.is_vulnerable and metrics['points']:
			for point in metrics['points']:
				vulnerability_sink.add(point)

	return function
