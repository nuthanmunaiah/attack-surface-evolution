import os

from rpy2 import robjects

from app.analysis import configuration
from app.analysis.adapters import (
    AssociationResult, ModelingResult, Model, PredictionResult, TrackingResult
)

# Load custom external R library
robjects.r.source(
    os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'library.R'
    )
)
robjects.r('init.libraries()')


class Db(object):
    def __init__(self, settings):
        self.settings = settings
        self.connection = None

        self._connect = robjects.r('db.connect')
        self._disconnect = robjects.r('db.disconnect')
        self._query = robjects.r('db.get.data')

    def connect(self):
        if 'postgresql' in self.settings['ENGINE']:
            self.connection = self._connect(
                host=self.settings['HOST'], port=self.settings['PORT'],
                user=self.settings['USER'], password=self.settings['PASSWORD'],
                dbname=self.settings['NAME'], provider='PostgreSQL'
            )

    def disconnect(self):
        return self._disconnect(self.connection)

    def query(self, sql):
        if self.connection:
            return self._query(self.connection, sql)


class Tests(object):
    def __init__(self):
        self._association = robjects.r('association.test')
        self._tracking = robjects.r('tracking.test')

    def association(self, data, column, switch=configuration.SWITCH,
                    normalize_by=None):
        result = None

        if not normalize_by:
            result = self._association(data, column, switch)
        else:
            result = self._association(data, column, switch, normalize_by)

        return AssociationResult.from_robject(result)

    def tracking(self, data, metric, akeys, bkeys):
        result = None

        _akeys = robjects.vectors.StrVector(akeys)
        _bkeys = robjects.vectors.StrVector(bkeys)

        result = self._tracking(data, metric, _akeys, _bkeys)
        return TrackingResult.from_robject(result)


class Regression(object):
    def __init__(self):
        self._model = robjects.r('regression.model')
        self._predict = robjects.r('regression.predict')

    def model(self, train_data, test_data, fsets, control,
              switch=configuration.SWITCH):
        _fsets = robjects.vectors.ListVector.from_length(len(fsets))
        for (index, value) in enumerate(fsets):
            _fsets[index] = robjects.vectors.StrVector(value)

        result = self._model(train_data, test_data, _fsets, control, switch)
        return ModelingResult.from_robject(result)

    def predict(self, model, test_data, switch=configuration.SWITCH):
        result = self._predict(model, test_data, switch)
        return PredictionResult.from_robject(result)
