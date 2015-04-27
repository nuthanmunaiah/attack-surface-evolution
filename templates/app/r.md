Proximity Metrics
=================

|  Metric  |                    Proximity to Entry                     |                     Proximity to Exit                     |
| -------- | --------------------------------------------------------- | --------------------------------------------------------- |
| Revision |  Significant  |   p-value   | Median(vuln) | Median(neut) |  Significant  |   p-value   | Median(vuln) | Median(neut) |
| -------- | ------------- | ----------- | ------------ | ------------ | ------------- | ----------- | ------------ | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pten.significant }}       | {{ r.pten.p|stringformat:"6.5e" }} | {{ r.pten.median.vuln|stringformat:"12.6f" }} | {{ r.pten.median.neut|stringformat:"12.6f" }} |       {{ r.ptex.significant }}       | {{ r.ptex.p|stringformat:"6.5e" }} | {{ r.ptex.median.vuln|stringformat:"12.6f" }} | {{ r.ptex.median.neut|stringformat:"12.6f" }} |
{% endfor %}

Surface Coupling Metrics
========================

|  Metric  |                Surface Coupling with Entry                |                Surface Coupling with Exit                 |
| -------- | --------------------------------------------------------- | --------------------------------------------------------- |
| Revision |  Significant  |   p-value   | Median(vuln) | Median(neut) |  Significant  |   p-value   | Median(vuln) | Median(neut) |
| -------- | ------------- | ----------- | ------------ | ------------ | ------------- | ----------- | ------------ | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.scen.significant }}       | {{ r.scen.p|stringformat:"6.5e" }} | {{ r.scen.median.vuln|stringformat:"12.6f" }} | {{ r.scen.median.neut|stringformat:"12.6f" }} |       {{ r.scex.significant }}       | {{ r.scex.p|stringformat:"6.5e" }} | {{ r.scex.median.vuln|stringformat:"12.6f" }} | {{ r.scex.median.neut|stringformat:"12.6f" }} |
{% endfor %}

Page Rank Metrics
=================

Page Rank (10000 to 1)
----------------------

|  Metric  |                  cflow (1.0) & gprof (0.5)                |                  cflow (0.5) & gprof (1.0)                |
| -------- | --------------------------------------------------------- | --------------------------------------------------------- |
| Revision |  Significant  |   p-value   | Median(vuln) | Median(neut) |  Significant  |   p-value   | Median(vuln) | Median(neut) |
| -------- | ------------- | ----------- | ------------ | ------------ | ------------- | ----------- | ------------ | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pr_10k_1_hl.significant }}       | {{ r.pr_10k_1_hl.p|stringformat:"6.5e" }} | {{ r.pr_10k_1_hl.median.vuln|stringformat:"12.6e" }} | {{ r.pr_10k_1_hl.median.neut|stringformat:"12.6e" }} |       {{ r.pr_10k_1_lh.significant }}       | {{ r.pr_10k_1_lh.p|stringformat:"6.5e" }} | {{ r.pr_10k_1_lh.median.vuln|stringformat:"12.6e" }} | {{ r.pr_10k_1_lh.median.neut|stringformat:"12.6e" }} |
{% endfor %}

Note: Entry/exit points were assigned a personalization value of 10000 and all other nodes were assigned a personalization value of 1.

Page Rank (100 to 1)
--------------------

|  Metric  |                  cflow (1.0) & gprof (0.5)                |                 cflow (0.5) & gprof (1.0)                 |
| -------- | --------------------------------------------------------- | --------------------------------------------------------- |
| Revision |  Significant  |   p-value   | Median(vuln) | Median(neut) |  Significant  |   p-value   | Median(vuln) | Median(neut) |
| -------- | ------------- | ----------- | ------------ | ------------ | ------------- | ----------- | ------------ | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{ r.pr_100_1_hl.significant }}       | {{ r.pr_100_1_hl.p|stringformat:"6.5e" }} | {{ r.pr_100_1_hl.median.vuln|stringformat:"12.6e" }} | {{ r.pr_100_1_hl.median.neut|stringformat:"12.6e" }} |       {{ r.pr_100_1_lh.significant }}       | {{ r.pr_100_1_lh.p|stringformat:"6.5e" }} | {{ r.pr_100_1_lh.median.vuln|stringformat:"12.6e" }} | {{ r.pr_100_1_lh.median.neut|stringformat:"12.6e" }} |
{% endfor %}

Note: Entry/exit points were assigned a personalization value of 100 and all other nodes were assigned a personalization value of 1.

Legend
======

Significant
-----------

 Y - Metric significantly correlated with vulnerable functions.
 N - No evidence of the metric being correlated with vulnerable functions.
 X - Population of vulnerable functions with finite value for the metric not present.
