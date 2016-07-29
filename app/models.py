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

    @property
    def past_vulnerability_fixes(self):
        if not hasattr(self, '_past_fixes'):
            self._past_fixes = set()

            for release in Release.objects.filter(subject=self.subject):
                if release <= self:
                    for cve_release in release.cverelease_set.all():
                        self._past_fixes.update(set(
                                cve_release.vulnerabilityfix_set.all()
                            ))

        return self._past_fixes

    @property
    def future_vulnerability_fixes(self):
        if not hasattr(self, '_future_fixes'):
            self._future_fixes = set()

            for release in Release.objects.filter(subject=self.subject):
                if release > self:
                    for cve_release in release.cverelease_set.all():
                        self._future_fixes.update(set(
                                cve_release.vulnerabilityfix_set.all()
                            ))

        return self._future_fixes

    @property
    def version(self):
        return '{0}.{1}.{2}'.format(self.major, self.minor, self.patch)

    def __str__(self):
        return '{0} v{1}'.format(self.subject, self.version)

    def __repr__(self):
        return str(self)

    def __lt__(self, other):
        if self.subject != other.subject:
            raise Exception('Cannot compare releases of different subjects')

        outcome = (
                self.date < other.date and
                (
                    self.major < other.major or
                    (
                        self.major == other.major and
                        self.minor < other.minor
                    ) or
                    (
                        self.major == other.major and
                        self.minor == other.minor and
                        self.patch < other.patch
                    )
                )
            )
        return outcome

    def __le__(self, other):
        return (self < other or self == other)

    def __eq__(self, other):
        outcome = (
                self.subject == other.subject and self.date == other.date and
                self.major == other.major and self.minor == other.minor and
                self.patch == other.patch
            )
        return outcome

    def __ne__(self, other):
        outcome = (
                self.subject != other.subject or self.date != other.date or
                self.major != other.major or self.minor != other.minor or
                self.patch != other.patch
            )
        return outcome

    def __gt__(self, other):
        if self.subject != other.subject:
            raise Exception('Cannot compare releases of different subjects')

        outcome = (
                self.date > other.date and
                self.major == other.major and
                self.minor == other.minor and
                self.patch > other.patch
            )
        return outcome

    def __ge__(self, other):
        return (self > other or self == other)

    class Meta:
        unique_together = ('subject', 'major', 'minor', 'patch')
        app_label = 'app'
        db_table = 'release'


class ReleaseStatistics(models.Model):
    release = models.ForeignKey(Release, db_index=True)

    granularity = models.CharField(max_length=10, null=False)

    monolithicity = models.FloatField(default=None, null=True)
    num_entry_points = models.PositiveIntegerField(default=None, null=True)
    num_exit_points = models.PositiveIntegerField(default=None, null=True)
    num_nodes = models.PositiveIntegerField(default=None, null=True)
    num_fragments = models.PositiveIntegerField(default=None, null=True)

    class Meta:
        unique_together = ('release', 'granularity')
        app_label = 'app'
        db_table = 'release_statistics'


class File(models.Model):
    release = models.ForeignKey(Release, db_index=True)
    name = models.CharField(max_length=100, db_index=True)

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

    frequency = models.PositiveSmallIntegerField(default=0)

    proximity_to_entry = models.FloatField(default=None, null=True)
    proximity_to_exit = models.FloatField(default=None, null=True)
    proximity_to_defense = models.FloatField(default=None, null=True)
    proximity_to_dangerous = models.FloatField(default=None, null=True)

    page_rank = models.FloatField(default=None, null=True)

    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)

    class Meta:
        app_label = 'app'
        db_table = 'file'


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

    frequency = models.PositiveSmallIntegerField(default=0)

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

    @property
    def identity(self):
        return '{0}@{1}'.format(self.name, self.file)

    def __str__(self):
        return self.identity

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(self.identity)

    def __eq__(self, other):
        return hash(self.identity) == hash(other.identity)

    class Meta:
        unique_together = ('cve_release', 'name', 'file')
        app_label = 'app'
        db_table = 'vulnerability_fix'


class Sensitivity(models.Model):
    release = models.ForeignKey(Release)

    damping = models.FloatField()

    personalization_entry = models.PositiveIntegerField()
    personalization_exit = models.PositiveIntegerField()
    personalization_other = models.PositiveIntegerField()

    weight_call = models.IntegerField()
    weight_return = models.IntegerField()
    weight_dangerous = models.IntegerField()
    weight_defense = models.IntegerField()
    weight_tested = models.IntegerField()
    weight_vulnerable = models.IntegerField()

    p = models.FloatField()
    d = models.FloatField()

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        self_str = (
                'd:{0}|en:{1} ex:{2} oth:{3}|'
                'ca:{4} re:{5} da:{6} de:{7} ts:{8} vu:{9}'
            ).format(
                    self.damping,
                    self.personalization_entry,
                    self.personalization_exit,
                    self.personalization_other,
                    self.weight_call,
                    self.weight_return,
                    self.weight_dangerous,
                    self.weight_defense,
                    self.weight_tested,
                    self.weight_vulnerable
                )

        return self_str

    def __repr__(self):
        return str(self)

    class Meta:
        app_label = 'app'
        db_table = 'sensitivity'
