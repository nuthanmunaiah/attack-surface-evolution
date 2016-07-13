import os
import sys
import traceback

from django.conf import settings
from django.db.models import Min
from django.template.loader import render_to_string

from app.analysis import configuration, helpers
from app.models import *


def run(database='default', fname=None):
    status = 0

    db = helpers.Db(settings.DATABASES[database])
    tests = helpers.Tests()
    regression = helpers.Regression()

    try:
        db.connect()

        templatedata = dict()
        templatedata['subjects'] = list()
        for item in settings.ENABLED_SUBJECTS:
            subject = Subject.objects.get(name=item)
            releases = Release.objects.filter(
                subject=subject, is_loaded=True
            )
            if releases.count() == 0:
                continue

            _subject = {'name': item, 'revisions': list(), 'tracking': list()}

            aggregate = releases.aggregate(Min('id'))
            minid = aggregate['id__min']
            releases = list(releases.order_by('-id'))
            index = 0
            while index < len(releases):
                release = releases[index]

                functions = Function.objects.filter(release=release)
                result = {'number': release.version}

                # Association tests
                trdata = db.query(configuration.BASE_SQL.format(release.pk))

                result['pen'] = tests.association(
                    trdata, 'proximity_to_entry'
                )
                result['pex'] = tests.association(
                    trdata, 'proximity_to_exit'
                )
                if functions.filter(is_defense=True).count() > 0:
                    result['pde'] = tests.association(
                        trdata, 'proximity_to_defense'
                    )
                result['pda'] = tests.association(
                    trdata, 'proximity_to_dangerous'
                )
                result['pr'] = tests.association(trdata, 'page_rank')

                # Logistic regression
                # teid = (
                #         releases[index + 1].pk
                #         if release.pk != minid else release.pk
                #     )
                # tedata = db.query(configuration.MODELING_SQL.format(teid))

                # model = regression.model(
                #     trdata, tedata,
                #     configuration.FEATURE_SETS, configuration.CONTROL
                # )
                # result['model'] = model

                _subject['revisions'].append(result)

                index += 1

            templatedata['subjects'].append(_subject)

        summary = render_to_string('app/r.md', templatedata)

        if fname:
            with open(fname, 'w+') as _file:
                _file.write(summary)
        else:
            print(summary)
    except Exception as e:
        _, _, _tb = sys.exc_info()
        sys.stderr.write('{}\n'.format(str(e)))
        traceback.print_tb(_tb)
        status = 2
    finally:
        db.disconnect()

    return status
