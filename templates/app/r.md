{% for s in subjects %}Subject: {{ s.name|stringformat:"-9s" }}
==================
{% with revisions=s.revisions %}
Association
===========

Proximity
=========

|  Metric  |                            Proximity to Entry                              |                              Proximity to Exit                             |
| -------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Revision |  Significant  |   p-value   |   Effect   | Median(vuln) |   | Median(neut) |  Significant  |   p-value   |   Effect   | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ---------- | ------------ | - | ------------ | ------------- | ----------- | ---------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pen.is_significant }}       | {{ r.pen.p|stringformat:"6.5e" }} | {{ r.pen.effect|center:"10" }} | {{ r.pen.vmedian|stringformat:"12.6f" }} | {{ r.pen.rel_median }} | {{ r.pen.nmedian|stringformat:"12.6f" }} |       {{ r.pex.is_significant }}       | {{ r.pex.p|stringformat:"6.5e" }} | {{ r.pex.effect|center:"10" }} | {{ r.pex.vmedian|stringformat:"12.6f" }} | {{ r.pex.rel_median }} | {{ r.pex.nmedian|stringformat:"12.6f" }} |
{% endfor %}

|  Metric  |                     Proximity to Designed Defenses                         |                      Proximity to Dangerous Functions                      |
| -------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Revision |  Significant  |   p-value   |   Effect   | Median(vuln) |   | Median(neut) |  Significant  |   p-value   |   Effect   | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ---------- | ------------ | - | ------------ | ------------- | ----------- | ---------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pde.is_significant }}       | {{ r.pde.p|stringformat:"6.5e" }} | {{ r.pde.effect|center:"10" }} | {{ r.pde.vmedian|stringformat:"12.6f" }} | {{ r.pde.rel_median }} | {{ r.pde.nmedian|stringformat:"12.6f" }} |       {{ r.pda.is_significant }}       | {{ r.pda.p|stringformat:"6.5e" }} | {{ r.pda.effect|center:"10" }} | {{ r.pda.vmedian|stringformat:"12.6f" }} | {{ r.pda.rel_median }} | {{ r.pda.nmedian|stringformat:"12.6f" }} |
{% endfor %}

Page Rank
=========

| Revision |  Significant  |   p-value   |   Effect   | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ---------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{r.pr.is_significant }}       | {{ r.pr.p|stringformat:"6.5e" }} | {{ r.pr.effect|center:"10" }} | {{ r.pr.vmedian|stringformat:"12.6e" }} | {{ r.pr.rel_median  }} | {{ r.pr.nmedian|stringformat:"12.6e" }} |
{% endfor %}

Tracking Tests
==============

|        Metric        |                                     Tracking                             |  Significant  |   p-value   |  Median(a)  |   |  Median(b)  |
| -------------------- | ------------------------------------------------------------------------ | ------------- | ----------- | ----------- | - | ----------- |
{% for t in s.tracking %}| {{ t.metric|stringformat:"-20s" }} | {{ t.comparing|stringformat:"-72s" }} |       {{ t.result.is_significant }}       | {{ t.result.p|stringformat:"6.5e" }} | {{ t.result.amedian|stringformat:"11.6e" }} | {{ t.result.rel_median  }} | {{ t.result.bmedian|stringformat:"11.6e" }} | 
{% endfor %} 

Legend
======

Significant
-----------

 Y - Metric is significantly correlated with vulnerable functions.
 N - No evidence of the metric being correlated with vulnerable functions.
 X - Population of vulnerable functions with finite value for the metric not present.


Regression
==========

Modeling
========

{% for r in revisions %}
 Revision   {{ r.number|stringformat:"8s" }} 
 Models
 ------

   |    AIC    |  % Change  | Formula                                                                                              | Precision | Recall | F-score |
   | --------- | ---------- | ---------------------------------------------------------------------------------------------------- | --------- | ------ | ------- |
   | {{ r.model.control.aic|stringformat:"9.4f" }} |     --     | {{ r.model.control.formula|stringformat:"-100s" }} |    ---    |   --   |   ---   |
   {% for m in r.model.models %}| {{ m.aic|stringformat:"9.4f" }} | {{ m.aic_change_pct|stringformat:"10.6f" }} | {{ m.formula|stringformat:"-100s" }} | {{ m.prediction_result.precision|stringformat:"9.4f"  }} | {{ m.prediction_result.recall|stringformat:"6.4f" }} | {{ m.prediction_result.fscore|stringformat:"7.4f" }} |
   {% endfor %}{% endfor %}{% endwith %}{% endfor %}
