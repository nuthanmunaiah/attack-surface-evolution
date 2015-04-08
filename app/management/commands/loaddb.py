from multiprocessing import Pool
from django.conf import settings
from django.core.management.base import BaseCommand

from app.models import Revision
from app.subjects.ffmpeg import FFmpeg
from app.utilities import load


class Command(BaseCommand):
    def handle(self, *args, **options):
        revisions = Revision.objects.filter(type='b')

        num_processes = min(settings.PARALLEL['PROCESSES'], revisions.count())
        
        with Pool(num_processes) as pool:
            pool.starmap(load, [(revision, FFmpeg) for revision in revisions])
