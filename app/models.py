from django.db import models

from app import constants

# TODO: Figure out a model to tie-up CVE fix to functions affected.

class Revision(models.Model):
    number = models.CharField(max_length=10, blank=False)
    type = models.CharField(max_length=4, choices=constants.REVISION_TYPE, blank=False)
    ref = models.CharField(max_length=50, blank=False)
    is_loaded = models.BooleanField(default=False)

    num_entry_points = models.PositiveIntegerField(default=0, blank=False)
    num_exit_points = models.PositiveIntegerField(default=0, blank=False)
    num_functions = models.PositiveIntegerField(default=0, blank=False)
    num_attack_surface_functions = models.PositiveIntegerField(default=0, blank=False)

    class Meta:
        unique_together = ('number', 'type')
        app_label = 'app'


class Function(models.Model):
    revision = models.ForeignKey(Revision, blank=False)
    name = models.CharField(max_length=52, blank=False)
    file = models.CharField(max_length=50, blank=False)
    is_entry = models.BooleanField(default=False)
    is_exit = models.BooleanField(default=False)
    is_tested = models.BooleanField(default=False)
    is_vulnerable = models.BooleanField(default=False)
    is_vulnerability_source = models.BooleanField(default=False)
    is_vulnerability_sink = models.BooleanField(default=False)
    is_connected_to_attack_surface = models.BooleanField(default=False)
    sloc = models.PositiveIntegerField(default=None, null=True)
    proximity_to_entry = models.FloatField(default=None, null=True)
    proximity_to_exit = models.FloatField(default=None, null=True)
    surface_coupling_with_entry = models.PositiveIntegerField(default=None, null=True)
    surface_coupling_with_exit = models.PositiveIntegerField(default=None, null=True)
    page_rank = models.FloatField(default=None, null=True)

    class Meta:
        app_label = 'app'


class Reachability(models.Model):
    type = models.CharField(max_length=8, choices=constants.REACHABILITY_TYPE, blank=False)
    function = models.ForeignKey(Function, blank=False)
    value = models.DecimalField(decimal_places=6, max_digits=10, blank=False)

    class Meta:
        app_label = 'app'


class Cve(models.Model):
    cve_id = models.CharField(max_length=13, blank=False)
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
