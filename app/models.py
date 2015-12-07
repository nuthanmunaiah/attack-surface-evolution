from django.db import models

from app import constants


class Subject(models.Model):
    name = models.CharField(max_length=10)
    remote = models.URLField()

    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)

    class Meta:
        app_label = 'app'
        db_table = 'subject'


class Branch(models.Model):
    subject = models.ForeignKey(Subject)

    major = models.PositiveIntegerField(default=0, blank=True)
    minor = models.PositiveIntegerField(default=0, blank=True)
    patch = models.PositiveIntegerField(default=0, blank=True)
    reference = models.CharField(max_length=50)

    configure_options = models.TextField(max_length=2000)

    @property
    def version(self):
        return '{0}.{1}.{2}'.format(self.major, self.minor, self.patch)

    def __str__(self):
        return '{0} b{1}'.format(self.subject, self.version)

    def __repr__(self):
        return str(self)

    class Meta:
        unique_together = ('subject', 'major', 'minor', 'patch')
        app_label = 'app'
        db_table = 'branch'


class Release(models.Model):
    subject = models.ForeignKey(Subject)
    branch = models.ForeignKey(Branch)

    date = models.DateField()

    major = models.PositiveIntegerField(default=0, blank=True)
    minor = models.PositiveIntegerField(default=0, blank=True)
    patch = models.PositiveIntegerField(default=0, blank=True)
    reference = models.CharField(max_length=50)

    is_loaded = models.BooleanField(default=False)
    monolithicity = models.FloatField(default=None, null=True)
    num_entry_points = models.PositiveIntegerField(default=None, null=True)
    num_exit_points = models.PositiveIntegerField(default=None, null=True)
    num_functions = models.PositiveIntegerField(default=None, null=True)
    num_fragments = models.PositiveIntegerField(default=None, null=True)

    @property
    def version(self):
        return '{0}.{1}.{2}'.format(self.major, self.minor, self.patch)

    def __str__(self):
        return '{0} v{1}'.format(self.subject, self.version)

    def __repr__(self):
        return str(self)

    def __lt__(self, other):
        return self.date < other.date

    def __le__(self, other):
        return self.date <= other.date

    def __eq__(self, other):
        return self.date == other.date

    def __ne__(self, other):
        return self.date != other.date

    def __gt__(self, other):
        return self.date > other.date

    def __ge__(self, other):
        return self.date >= other.date

    class Meta:
        unique_together = ('subject', 'major', 'minor', 'patch')
        app_label = 'app'
        db_table = 'release'


class Function(models.Model):
    release = models.ForeignKey(Release, db_index=True)
    name = models.CharField(max_length=125, db_index=True)
    file = models.CharField(max_length=100, db_index=True)

    is_entry = models.BooleanField(default=False)
    is_exit = models.BooleanField(default=False)
    is_tested = models.BooleanField(default=False)
    calls_dangerous = models.BooleanField(default=False)
    is_defense = models.BooleanField(default=False)

    was_vulnerable = models.BooleanField(default=False)
    becomes_vulnerable = models.BooleanField(default=False)

    sloc = models.PositiveIntegerField(default=None, null=True)

    fan_in = models.PositiveSmallIntegerField(null=False)
    fan_out = models.PositiveSmallIntegerField(null=False)

    proximity_to_entry = models.FloatField(default=None, null=True)
    proximity_to_exit = models.FloatField(default=None, null=True)
    proximity_to_defense = models.FloatField(default=None, null=True)
    proximity_to_dangerous = models.FloatField(default=None, null=True)
    
    page_rank = models.FloatField(default=None, null=True)

    def __str__(self):
        return '{0}@{1}'.format(self.name, self.file)

    def __repr__(self):
        return str(self)

    class Meta:
        app_label = 'app'
        db_table = 'function'


class Cve(models.Model):
    subject = models.ForeignKey(Subject)
    identifier = models.CharField(max_length=25)
    publish_dt = models.DateField()
    is_fixed = models.BooleanField(default=False)

    def __str__(self):
        return self.identifier

    def __repr__(self):
        return str(self)

    class Meta:
        app_label = 'app'
        db_table = 'cve'


class CveRelease(models.Model):
    cve = models.ForeignKey(Cve)
    release = models.ForeignKey(Release)
    fix_sha = models.CharField(max_length=40)

    class Meta:
        app_label = 'app'
        db_table = 'cve_release'


class VulnerabilityFix(models.Model):
    cve_release = models.ForeignKey(CveRelease)

    name = models.CharField(max_length=125)
    file = models.CharField(max_length=100)

    def __str__(self):
        return '{0}@{1}'.format(self.name, self.file)

    def __repr__(self):
        return str(self)

    class Meta:
        unique_together = ('cve_release', 'name', 'file')
        app_label = 'app'
        db_table = 'vulnerability_fix'
