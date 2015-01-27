from django.db import models

from app import constants

# TODO: Figure out a model to tie-up CVE fix to functions affected.

class Revision(models.Model):
    number = models.CharField(max_length=10, blank=False)
    type = models.CharField(max_length=4, choices=constants.REVISION_TYPE, blank=False)
    ref = models.CharField(max_length=50, blank=False)
    date = models.DateField(blank=False)
    is_loaded = models.BooleanField(default=False)

    num_entry_points = models.PositiveIntegerField(default=0, blank=False)
    num_exit_points = models.PositiveIntegerField(default=0, blank=False)
    num_functions =  models.PositiveIntegerField(default=0, blank=False)
    num_reachable_functions = models.PositiveIntegerField(default=0, blank=False)

    class Meta:
        unique_together = ('number', 'type')


class Function(models.Model):
    revision = models.ForeignKey(Revision, blank=False)
    name = models.CharField(max_length=52, blank=False)
    file = models.CharField(max_length=50, blank=False)
    is_entry = models.BooleanField(default=False)
    is_exit = models.BooleanField(default=False)
    is_vulnerable = models.BooleanField(default=False)
    min_dist_to_entry = models.PositiveIntegerField(default=None, null=True)
    max_dist_to_entry = models.PositiveIntegerField(default=None, null=True)
    avg_dist_to_entry = models.PositiveIntegerField(default=None, null=True)
    num_entry_points = models.PositiveIntegerField(default=None, null=True)
    min_dist_to_exit = models.PositiveIntegerField(default=None, null=True)
    max_dist_to_exit = models.PositiveIntegerField(default=None, null=True)
    avg_dist_to_exit = models.PositiveIntegerField(default=None, null=True)
    num_exit_points = models.PositiveIntegerField(default=None, null=True)
    attack_surface_betweenness = models.FloatField(default=None, null=True)


class Reachability(models.Model):
    type = models.CharField(max_length=4, choices=constants.REACHABILITY_TYPE, blank=False)
    function = models.ForeignKey(Function, blank=False)
    value = models.DecimalField(decimal_places=6, max_digits=10, blank=False)


class Cve(models.Model):
    cve_id = models.CharField(max_length=13, blank=False)
    publish_dt = models.DateField(blank=False)
    is_fixed = models.BooleanField(default=False)


class CveRevision(models.Model):
    cve = models.ForeignKey(Cve, blank=False)
    revision = models.ForeignKey(Revision)
    commit_hash = models.CharField(max_length=40, blank=False)