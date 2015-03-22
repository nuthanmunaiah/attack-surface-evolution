import threading
from django.conf import settings
from django.db import connection
from queue import Queue

from app import constants
from app.models import Revision
from app.subjects.ffmpeg import FFmpeg

def load(revision):
	# TODO: Revisit call to connection.close()
	connection.close()

	ffmpeg = FFmpeg(settings.NUM_CORES, revision.ref)
	ffmpeg.prepare()
	
	# TODO: Parallelize get_call_graph, get_vulnerable_functions, and
	# 	get_function_sloc
	call_graph = ffmpeg.get_call_graph()
	vuln_funcs = get_vulnerable_functions(revision)
	# TODO: Uncomment when a sustainable approach to managing function SLOC
	# 	computation is devised
	# func_sloc = get_function_sloc(revision)
	func_sloc = None
	
	process(revision, call_graph, vuln_funcs, func_sloc)

def process(revision, call_graph, vuln_funcs, func_sloc):
	vulnerability_source = set()
	vulnerability_sink = set()

	with transaction.atomic():
		# Process entry points
		for node in call_graph.entry_points
			function = process_node(node)

			r = Reachability()
			r.type = constants.RT_EN
			r.function = function
			r.value = call_graph.get_entry_point_reachability(node)
			r.save()

			# TODO: Consider removing Shallow Reachability
			r = Reachability()
			r.type = constants.RT_SHEN_ONE
			r.function = function
			r.value = call_graph.get_shallow_entry_point_reachability(node)
			r.save()
			
			# TODO: Consider removing Shallow Reachability
			r = Reachability()
			r.type = constants.RT_SHEN_TWO
			r.function = function
			r.value = call_graph.get_shallow_entry_point_reachability(node, depth=2)
			r.save()

			function.save()

		# Process exit points
		for node in call_graph.entry_points
			function = process_node(node)

			expr = Reachability()
			expr.type = constants.RT_EX
			expr.function = function
			expr.value = call_graph.get_exit_point_reachability(node)
			expr.save()

			function.save()

		for node in call_graph.nodes:
			function = process(node, call_graph)
			function.save()
			
		revision.num_entry_points = len(call_graph.entry_points)
		revision.num_exit_points = len(call_graph.exit_points)
		revision.num_functions = len(call_graph.nodes)
		revision.num_attack_surface_functions = len(
			call_graph.attack_surface_graph_nodes)
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

def process(node, call_graph):
	function = Function()

	function.revision = revision
	function.name = node.function_name
	function.file = node.function_signature
	function.is_entry = node in call_graph.entry_points
	function.is_exit = node in call_graph.exit_points
	function.is_vulnerable = \
		(
			node.function_signature in vuln_funcs and
			node.function_name in vuln_funcs[node.function_signature]
		)

	# # Fully qualified name of the node in the form function_name@file_name
	# fq_name = '%s@%s' % (node.function_name, node.function_signature)
	# if fq_name in func_sloc:
	# 	function.sloc = func_sloc[fq_name]

	if node in call_graph.attack_surface_graph_nodes:
		function.is_connected_to_attack_surface = True

		metrics = call_graph.get_entry_surface_metrics(node)
		function.proximity_to_entry = metrics['proximity']
		function.surface_coupling_with_entry = metrics['surface_coupling']

		if function.is_vulnerable and metrics['points']:
			for point in metrics['points']:
				vulnerability_source.add(point)

		metrics = call_graph.get_exit_surface_metrics(node)
		function.proximity_to_exit = metrics['proximity']
		function.surface_coupling_with_exit = metrics['surface_coupling']

		if function.is_vulnerable and metrics['points']:
			for point in metrics['points']:
				vulnerability_sink.add(point)

	return function

def get_vulnerable_functions(revision, subject):
	cve_revisions = None
	if revision.type == constants.RT_TAG:
		cve_revisions = CveRevision.objects.filter(revision=revision)
	elif revision.type == constants.RT_BRANCH:
		(major, minor, build) = get_version_components(revision.number)
		
		cve_revisions = CveRevision.objects.filter(
			revision__number__startswith='%d.%d' % (major, minor)
		)

	vuln_funcs = dict()
	for cve_revision in cve_revisions:
		for file_ in subject.repo.get_files_changed(cve_revision.commit_hash):

			# TODO: Update to work with file paths instead of file names
			file_name = os.path.basename(subject.get_file_path(file_))
			
			if file_name not in vuln_funcs:
				vuln_funcs[file_name] = set()
			for function in subject.repo.get_functions_changed(
				cve_revision.commit_hash, file=file_):

				vuln_funcs[file_name].add(function)

	return vuln_funcs

def get_function_sloc(revision):
	re_function = re.compile('^([^\(]*)')
	sloc_file = os.path.join(self.workspace_path, constants.FUNC_SLOC_FILE_PATTERN % revision.number)

	if not os.path.exists(sloc_file):
		raise CommandError('Function SLOC file not found at %s.' % self.workspace_path)

	function_sloc = dict()
	with open(sloc_file, 'r') as _sloc_file:
		reader = csv.reader(_sloc_file)
		next(reader)  # Skipping the header
		for row in reader:
			function = re_function.match(row[1]).group(1)
			file = row[0][row[0].rfind('\\') + 1:]
			function_sloc['%s@%s' % (function, file)] = int(row[3])

	return function_sloc

def get_version_components(string):
	major = 0
	minor = 0
	build = 0
	match = constants.RE_REV_NUM.search(string)
	if not match:
		raise InvalidVersion(string)
	else:
		groups = match.groups()
		major = int(groups[0])
		if groups[1]: minor = int(groups[1])
		if groups[2]: build = int(groups[2])

	return (major, minor, build)
