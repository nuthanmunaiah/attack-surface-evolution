from django.utils.safestring import mark_safe

class AssociationResult(object):
    def __init__(self):
        self.p = 0.0
        self._is_significant = False

        self.vmean = 0.0
        self.nmean = 0.0
        self._rel_mean = '='

        self.vmedian = 0.0
        self.nmedian = 0.0
        self._rel_median = '='

    @property
    def is_significant(self):
        return 'Y' if self._is_significant else 'N'

    @property
    def rel_mean(self):
        return mark_safe(self._rel_mean)

    @property
    def rel_median(self):
        return mark_safe(self._rel_median)

    @staticmethod
    def from_robject(robject):
        _instance = AssociationResult()

        if robject:
            _instance.p = robject.do_slot('p')[0]
            _instance._is_significant = _instance.p <= 0.01

            _instance.vmean = robject.do_slot('true.mean')[0]
            _instance.nmean = robject.do_slot('false.mean')[0]
            if _instance.vmean > _instance.nmean:
                _instance._rel_mean = '>'
            elif _instance.vmean < _instance.nmean:
                _instance._rel_mean = '<'

            _instance.vmedian = robject.do_slot('true.median')[0]
            _instance.nmedian = robject.do_slot('false.median')[0]
            if _instance.vmedian > _instance.nmedian:
                _instance._rel_median = '>'
            elif _instance.vmedian < _instance.nmedian:
                _instance._rel_median = '<'

        return _instance

class Model(object):
    def __init__(self):
        self.model = None
        self.formula = None
        self.aic = 0.0
        self.aic_change_pct = 0.0
        self.prediction_result = None

    @staticmethod
    def from_robject(robject):
        _instance = Model()

        if robject:
            _instance.formula = robject.do_slot('formula')[0]
            _instance.aic = robject.do_slot('aic')[0]
            _instance.aic_change_pct = robject.do_slot('aic.change.pct')[0]
            _instance.prediction_result = PredictionResult.from_robject(
                robject.do_slot('prediction.result')
            )

        return _instance


class ModelingResult(object):
    def __init__(self):
        self.control = None
        self.models = None

    @staticmethod
    def from_robject(robject):
        _instance = ModelingResult()

        if robject:
            _instance.control = Model.from_robject(robject.do_slot('control'))
            _models = robject.do_slot('models')
            if _models:
                _instance.models = list()
                for _model in _models:
                    _instance.models.append(Model.from_robject(_model))

        return _instance


class PredictionResult(object):
    def __init__(self):
        self.precision = 0.0
        self.recall = 0.0
        self.fscore = 0.0

    @staticmethod
    def from_robject(robject):
        _instance = PredictionResult()

        _instance.precision = robject.do_slot('precision')[0]
        _instance.recall = robject.do_slot('recall')[0]
        _instance.fscore = robject.do_slot('fscore')[0]

        return _instance


class TrackingResult(object):
    def __init__(self):
        self.p = 0.0
        self._is_significant = False

        self.amean = 0.0
        self.bmean = 0.0
        self._rel_mean = '='

        self.amedian = 0.0
        self.bmedian = 0.0
        self._rel_median = '='

    @property
    def is_significant(self):
        return 'Y' if self._is_significant else 'N'

    @property
    def rel_mean(self):
        return mark_safe(self._rel_mean)

    @property
    def rel_median(self):
        return mark_safe(self._rel_median)

    @staticmethod
    def from_robject(robject):
        _instance = TrackingResult()

        if robject:
            _instance.p = robject.do_slot('p')[0]
            _instance._is_significant = _instance.p <= 0.01

            _instance.amean = robject.do_slot('a.mean')[0]
            _instance.bmean = robject.do_slot('b.mean')[0]
            if _instance.amean > _instance.bmean:
                _instance._rel_mean = '>'
            elif _instance.amean < _instance.bmean:
                _instance._rel_mean = '<'

            _instance.amedian = robject.do_slot('a.median')[0]
            _instance.bmedian = robject.do_slot('b.median')[0]
            if _instance.amedian > _instance.bmedian:
                _instance._rel_median = '>'
            elif _instance.amedian < _instance.bmedian:
                _instance._rel_median = '<'

        return _instance
