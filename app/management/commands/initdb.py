import os, re, csv, datetime, re
from optparse import make_option
from django.db import transaction
from django.core.management.base import BaseCommand, CommandError

from app import utilities


class Command(BaseCommand):
	# TODO: Add help text to the options.
	option_list = BaseCommand.option_list + (
		make_option('-r', '--reset',
					dest='reset',
					action='store_true',
					default=False,
					help='reset HELP.'),
	)
	help = 'initdb HELP.'

	def handle(self, *args, **options):
		self.verbosity = int(options.get('verbosity'))
		self.reset = bool(options.get('reset'))

		if self.reset:
			Revision.objects.all().delete()
			Cve.objects.all().delete()

		utilities.load_revisions()
		utilities.load_cves()
		utilities.map_cve_to_revision()
