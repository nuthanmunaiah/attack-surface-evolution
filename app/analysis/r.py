import os
import sys
import traceback

from django.conf import settings
from django.db.models import Max
from django.template.loader import render_to_string

from app.analysis import constants, helpers
from app.models import Function, Revision, Subject


def run(database='default', fname=None):
    status = 0

    db = helpers.Db(settings.DATABASES[database])
    tests = helpers.Tests()
    regression = helpers.Regression()

    try:
        db.connect()

        templatedata = dict()
        templatedata['subjects'] = list()
        for item in settings.SUBJECTS:
            subject = Subject.objects.get(name=item)
            revisions = Revision.objects.filter(
                subject=subject, is_loaded=True
            )
            if revisions.count() == 0:
                continue

            _subject = {'name': item, 'revisions': list(), 'tracking': list()}

            aggregate = revisions.aggregate(Max('id'))
            maxid = aggregate['id__max']
            for revision in revisions.order_by('id'):
                functions = Function.objects.filter(revision=revision)
                result = {'number': revision.number}

                # Association tests
                trdata = db.query(constants.BASE_SQL.format(revision.pk))

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
                teid = revision.pk + 1 if revision.pk < maxid else revision.pk
                tedata = db.query(constants.MODELING_SQL.format(teid))

                model = regression.model(
                    trdata, tedata, constants.FEATURE_SETS, constants.CONTROL
                )
                result['model'] = model

                _subject['revisions'].append(result)

            # Tracking validation
            data = db.query(constants.TRACKING_SQL.format(subject.pk))
            for (metric, akeys, bkeys) in constants.TRACKING_SETS:
                result = {
                    'metric': metric,
                    'comparing': '({0}) vs. ({1})'.format(
                        ','.join(akeys), ','.join(bkeys)
                    )
                }
                result['result'] = tests.tracking(data, metric, akeys, bkeys)
                _subject['tracking'].append(result)

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
