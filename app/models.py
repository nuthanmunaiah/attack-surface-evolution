from django.db import models

from app import constants

# TODO: Figure out a model to tie-up CVE fix to functions affected.


class Subject(models.Model):
    name = models.CharField(max_length=10, blank=False)


class Revision(models.Model):
    subject = models.ForeignKey(Subject, blank=False)
    number = models.CharField(max_length=10, blank=False)
    type = models.CharField(
        max_length=4, choices=constants.REVISION_TYPE, blank=False
    )
    ref = models.CharField(max_length=50, blank=False)
    is_loaded = models.BooleanField(default=False)
    configure_options = models.TextField(max_length=2000, blank=False)

    monolithicity = models.FloatField(default=0.0, blank=False)
    num_entry_points = models.PositiveIntegerField(default=0, blank=False)
    num_exit_points = models.PositiveIntegerField(default=0, blank=False)
    num_functions = models.PositiveIntegerField(default=0, blank=False)
    num_fragments = models.PositiveIntegerField(default=0, blank=False)

    class Meta:
        unique_together = ('subject', 'number', 'type')
        app_label = 'app'


class Function(models.Model):
    revision = models.ForeignKey(Revision, blank=False, db_index=True)
    name = models.CharField(max_length=125, blank=False, db_index=True)
    file = models.CharField(max_length=100, blank=False, db_index=True)

    is_entry = models.BooleanField(default=False)
    is_exit = models.BooleanField(default=False)
    is_tested = models.BooleanField(default=False)
    calls_dangerous = models.BooleanField(default=False)
    is_defense = models.BooleanField(default=False)
    is_vulnerable = models.BooleanField(default=False)

    sloc = models.PositiveIntegerField(default=None, null=True)

    fan_in = models.PositiveSmallIntegerField(null=False)
    fan_out = models.PositiveSmallIntegerField(null=False)

    proximity_to_entry = models.FloatField(default=None, null=True)
    proximity_to_exit = models.FloatField(default=None, null=True)
    proximity_to_defense = models.FloatField(default=None, null=True)
    proximity_to_dangerous = models.FloatField(default=None, null=True)
    page_rank_b = models.FloatField(default=None, null=True)
    page_rank_bv = models.FloatField(default=None, null=True)
    page_rank_bvd = models.FloatField(default=None, null=True)
    page_rank_bvdt = models.FloatField(default=None, null=True)
    page_rank_bvdtd = models.FloatField(default=None, null=True)

    class Meta:
        app_label = 'app'


class Cve(models.Model):
    subject = models.ForeignKey(Subject, blank=False)
    cve_id = models.CharField(max_length=25, blank=False)
    publish_dt = models.DateField(blank=False)
    is_fixed = models.BooleanField(default=False)

    class Meta:
        app_label = 'app'


class CveRevision(models.Model):
    cve = models.ForeignKey(Cve, blank=False)
    revision = models.ForeignKey(Revision)
    commit_hash = models.CharField(max_length=40, blank=False)

    class Meta:
        app_label = 'app'
