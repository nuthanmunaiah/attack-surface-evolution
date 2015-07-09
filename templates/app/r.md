Proximity
=========

|  Metric  |                       Proximity to Entry                      |                       Proximity to Exit                       |
| -------- | ------------------------------------------------------------- | ------------------------------------------------------------- |
| Revision |  Significant  |   p-value   | Median(vuln) |   | Median(neut) |  Significant  |   p-value   | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ------------ | - | ------------ | ------------- | ----------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pten.significant }}       | {{ r.pten.p|stringformat:"6.5e" }} | {{ r.pten.median.vuln|stringformat:"12.6f" }} | {{ r.pten.rel }} | {{ r.pten.median.neut|stringformat:"12.6f" }} |       {{ r.ptex.significant }}       | {{ r.ptex.p|stringformat:"6.5e" }} | {{ r.ptex.median.vuln|stringformat:"12.6f" }} | {{ r.ptex.rel }} | {{ r.ptex.median.neut|stringformat:"12.6f" }} |
{% endfor %}

|  Metric  |               Proximity to Designed Defenses                  |               Proximity to Dangerous Functions                |
| -------- | ------------------------------------------------------------- | ------------------------------------------------------------- |
| Revision |  Significant  |   p-value   | Median(vuln) |   | Median(neut) |  Significant  |   p-value   | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ------------ | - | ------------ | ------------- | ----------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.ptde.significant }}       | {{ r.ptde.p|stringformat:"6.5e" }} | {{ r.ptde.median.vuln|stringformat:"12.6f" }} | {{ r.ptde.rel }} | {{ r.ptde.median.neut|stringformat:"12.6f" }} |       {{ r.ptda.significant }}       | {{ r.ptda.p|stringformat:"6.5e" }} | {{ r.ptda.median.vuln|stringformat:"12.6f" }} | {{ r.ptda.rel }} | {{ r.ptda.median.neut|stringformat:"12.6f" }} |
{% endfor %}

Page Rank
=========

| Revision |  Significant  |   p-value   | Median(vuln) |   | Median(neut) |
| -------- | ------------- | ----------- | ------------ | - | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{r.page_rank.significant }}       | {{ r.page_rank.p|stringformat:"6.5e" }} | {{ r.page_rank.median.vuln|stringformat:"12.6e" }} | {{ r.page_rank.rel  }} | {{ r.page_rank.median.neut|stringformat:"12.6e" }} |
{% endfor %}

Legend
======

Significant
-----------

 Y - Metric significantly correlated with vulnerable functions.
 N - No evidence of the metric being correlated with vulnerable functions.
 X - Population of vulnerable functions with finite value for the metric not present.
