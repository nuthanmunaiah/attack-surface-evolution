{% for s in subjects %}Subject: {{ s.name|stringformat:"-9s" }}
==================
{% with revisions=s.revisions %}
Association
===========

Proximity
=========

|  Metric  |                                    Proximity to Entry                                 |                                    Proximity to Exit                                  |
| -------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Revision |  Significant  |   p-value   |   Effect   | Cohens d | Median(vuln) |   | Median(neut) |  Significant  |   p-value   |   Effect   | Cohens d | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ---------- | -------- | ------------ | - | ------------ | ------------- | ----------- | ---------- | -------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pen.is_significant }}       | {{ r.pen.p|stringformat:"6.5e" }} | {{ r.pen.effect|center:"10" }} | {{r.pen.cohensd|stringformat:"8.4f"}} | {{ r.pen.vmedian|stringformat:"12.6f" }} | {{ r.pen.rel_median }} | {{ r.pen.nmedian|stringformat:"12.6f" }} |       {{ r.pex.is_significant }}       | {{ r.pex.p|stringformat:"6.5e" }} | {{ r.pex.effect|center:"10" }} | {{r.pex.cohensd|stringformat:"8.4f"}} | {{ r.pex.vmedian|stringformat:"12.6f" }} | {{ r.pex.rel_median }} | {{ r.pex.nmedian|stringformat:"12.6f" }} |
{% endfor %}

|  Metric  |                           Proximity to Designed Defenses                               |                            Proximity to Dangerous Functions                          |
| -------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Revision |  Significant  |   p-value   |   Effect   | Cohens d | Median(vuln) |   | Median(neut) |  Significant  |   p-value   |   Effect   | Cohens d | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ---------- | -------- | ------------ | - | ------------ | ------------- | ----------- | ---------- | -------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pde.is_significant }}       | {{ r.pde.p|stringformat:"6.5e" }} | {{ r.pde.effect|center:"10" }} | {{r.pde.cohensd|stringformat:"8.4f"}} | {{ r.pde.vmedian|stringformat:"12.6f" }} | {{ r.pde.rel_median }} | {{ r.pde.nmedian|stringformat:"12.6f" }} |       {{ r.pda.is_significant }}       | {{ r.pda.p|stringformat:"6.5e" }} | {{ r.pda.effect|center:"10" }} | {{r.pda.cohensd|stringformat:"8.4f"}} | {{ r.pda.vmedian|stringformat:"12.6f" }} | {{ r.pda.rel_median }} | {{ r.pda.nmedian|stringformat:"12.6f" }} |
{% endfor %}

Page Rank
=========

| Revision |  Significant  |   p-value   |   Effect   | Cohens d | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ---------- | -------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{r.pr.is_significant }}       | {{ r.pr.p|stringformat:"6.5e" }} | {{ r.pr.effect|center:"10" }} | {{r.pr.cohensd|stringformat:"8.4f"}} | {{ r.pr.vmedian|stringformat:"12.6e" }} | {{ r.pr.rel_median  }} | {{ r.pr.nmedian|stringformat:"12.6e" }} |
{% endfor %}
{% endwith %}{% endfor %}
Legend
======

Significant
-----------

 Y - Metric is significantly correlated with vulnerable functions.
 N - No evidence of the metric being correlated with vulnerable functions.
 X - Population of vulnerable functions with finite value for the metric not present.
