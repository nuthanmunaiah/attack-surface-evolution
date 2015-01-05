import os, app


def get_absolute_path(dir_name):
    return os.path.join(app.__path__[0], dir_name)


def get_version_number(string):
    major = 0
    minor = 0
    build = 0
    match = constants.RE_REV_NUM.search(string)
    if not match:
        raise InvalidVersion(version)
    else:
        groups = match.groups()
        major = int(groups[0])
        if groups[1]: minor = int(groups[1])
        if groups[2]: build = int(groups[2])

    return '%d.%d.%d' % (major, minor, build)


class InvalidVersion(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)