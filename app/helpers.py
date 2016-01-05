import csv
import os
import sys

import numpy

from django.conf import settings

from app import constants, errors


def get_version_components(string):
    major = 0
    minor = 0
    build = 0
    match = constants.RE_REV_NUM.search(string)
    if not match:
        raise errors.InvalidVersionError(string)
    else:
        groups = match.groups()
        major = int(groups[0])
        if groups[1]:
            minor = int(groups[1])
        if groups[2]:
            build = int(groups[2])

    return (major, minor, build)


def get_absolute_path(dir_name):
    return os.path.join(settings.BASE_DIR, dir_name)


def generate_parameters(filepath):
    parameters_collection = list()

    other = 1   # Personalization value for all non-entry/exit functions

    # Damping factor from 10% to 90% with 5% increments
    for damping in numpy.arange(0.1, 1.0, 0.05):
        # Personalization from 1 to 1000000 increasing exponentially
        for power in range(0, 7):
            entry = 10 ** power
            for power in range(0, 7):
                exit = 10 ** power
                for power in range(0, 5):
                    call = 10 ** power
                    for power in range(0, 5):
                        retrn = 10 ** power
                        parameters_collection.append((
                            round(damping, 2), entry, exit, other, call, retrn
                        ))

    with open(filepath, 'w') as file_:
        writer = csv.writer(file_)
        writer.writerows(parameters_collection)


def debug(message, line=False):
    if 'DEBUG' in os.environ:
        if line:
            sys.stdout.write('\r\033[K')
            sys.stdout.write('[DEBUG] {0}'.format(message))
            sys.stdout.flush()
        else:
            print('[DEBUG] {0}'.format(message))
