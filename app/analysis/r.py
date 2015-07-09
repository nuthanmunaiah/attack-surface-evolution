import os
import sys
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe

from rpy2 import robjects, rinterface

from app.models import Revision, Function

# Aliasing the robjects.r singleton
r = robjects.r


def run(output_file):
    status = 0

    try:
        db_connect()

        results = dict()
        results['revisions'] = list()

        for revision in Revision.objects.filter(is_loaded=True).order_by('id'):
            result = dict()
            result['number'] = revision.number

            db_query(revision)

            result['pten'] = association(
                'proximity_to_entry', 'is_vulnerable', normalize=False
            )
            result['ptex'] = association(
                'proximity_to_exit', 'is_vulnerable', normalize=False
            )
            result['ptde'] = association(
                'proximity_to_defense', 'is_vulnerable', normalize=False
            )
            result['ptda'] = association(
                'proximity_to_dangerous', 'is_vulnerable', normalize=False
            )

            result['page_rank'] = association(
                'page_rank', 'is_vulnerable', normalize=False
            )

            results['revisions'].append(result)

        with open(output_file, 'w+') as _file:
            _file.write(render_to_string('app/r.md', results))
    except Exception as e:
        sys.stderr.write(e.msg)
        status = 2
    finally:
        db_disconnect()

    return status


def db_connect():
    # TODO: Allow for other providers
    rcode = '''
        library("DBI")
        library("RPostgreSQL")
        driver <- dbDriver("PostgreSQL")
        connection <- dbConnect(driver,
            host="%(HOST)s",
            port=%(PORT)s,
            user="%(USER)s",
            password="%(PASSWORD)s",
            dbname="%(NAME)s"
        )
    ''' % (settings.DATABASES['default'])

    r(rcode)


def db_disconnect():
    r('dbDisconnect(connection)')


def db_query(revision):
    rcode = '''
        dataset <- dbGetQuery(connection,
                    "SELECT * FROM app_function WHERE revision_id = %d")
    ''' % (revision.id)

    r(rcode)


def association(column, switch, normalize):
    result = None
    params = {'column': column, 'switch': switch}

    # Default
    result = {
        'significant': 'X',
        'p': 0,
        'mean': {'vuln': 0, 'neut': 0},
        'median': {'vuln': 0, 'neut': 0}
    }

    if normalize:
        rcode = '''
            vulnerable <- dataset$%(column)s[dataset$%(switch)s == "TRUE" &
                is.finite(dataset$%(column)s)]
            neutral <- dataset$%(column)s[dataset$%(switch)s == "FALSE" &
                is.finite(dataset$%(column)s)]

            vulnerable <- vulnerable /
                dataset$sloc[dataset$%(switch)s == "TRUE" &
                    is.finite(dataset$%(column)s)]
            neutral <- neutral /
                dataset$sloc[dataset$%(switch)s == "FALSE" &
                    is.finite(dataset$%(column)s)]

            vulnerable <- vulnerable[is.finite(vulnerable)]
            neutral <- neutral[is.finite(neutral)]

            htest <- wilcox.test(vulnerable, neutral)

            p <- htest$p.value
            v_mean <- mean(vulnerable)
            n_mean <- mean(neutral)
            v_median <- median(vulnerable)
            n_median <- median(neutral)
        ''' % (params)
    else:
        rcode = '''
            vulnerable <- dataset$%(column)s[dataset$%(switch)s == "TRUE" &
                is.finite(dataset$%(column)s)]
            neutral <- dataset$%(column)s[dataset$%(switch)s == "FALSE" &
                is.finite(dataset$%(column)s)]

            htest <- wilcox.test(vulnerable, neutral)

            p <- htest$p.value
            v_mean <- mean(vulnerable)
            n_mean <- mean(neutral)
            v_median <- median(vulnerable)
            n_median <- median(neutral)
        ''' % (params)

    try:
        r(rcode)
        result = {
            'significant': 'Y' if r['p'][0] <= 0.05 else 'N',
            'p': r['p'][0],
            'mean': {'vuln': r['v_mean'][0], 'neut': r['n_mean'][0]},
            'median': {'vuln': r['v_median'][0], 'neut': r['n_median'][0]},
            'rel': (
                mark_safe('<')
                if r['v_median'][0] < r['n_median'][0] else mark_safe('>')
            )
        }
    except rinterface.RRuntimeError as error:
        print('[ERROR]')

    return result

if __name__ == '__main__':
    run()
