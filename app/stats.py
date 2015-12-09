import math

import numpy


def cohensd(treatment, control, pooled=True):
    """Compute Cohen's d effect size measure between two samples.

    Parameters
    ----------
    treatment : numpy.ndarray
        An array containing metric values collected from the treatment group.
    control : numpy.ndarray
        An array containing metric values collected from the control group.
    pooled : bool, optional
        When True, the pooled standard deviation between the treatment and
        control groups will be used when computing Cohen's d. When False, it is
        assumed that both groups are drawn from the same distribution and have
        the same number of observations.

    Returns
    -------
    d : numpy.float64
        The Cohen's d effect size measure
    """
    if pooled:
        n1 = len(treatment)
        n2 = len(control)

        sd1 = numpy.std(treatment, ddof=1)
        sd2 = numpy.std(control, ddof=1)

        sd = math.sqrt(
                ((n1 - 1) * sd1 ** 2 + (n2 - 1) * sd2 ** 2) / (n1 + n2 - 2)
            )
    else:
        sd = numpy.std(numpy.concatenate((treatment, control)), ddof=1)

    return ((treatment.mean() - control.mean()) / sd)
