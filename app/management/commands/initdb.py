from django.core.management.base import BaseCommand
from django.db import transaction

from app import utilities


class Command(BaseCommand):
    help = 'initdb HELP.'

    def handle(self, *args, **options):
        with transaction.atomic():
            utilities.load_subjects()
            utilities.load_revisions()
            utilities.load_cves()
            utilities.map_cve_to_revision()
