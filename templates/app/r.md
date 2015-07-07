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

Page Rank
=========

| Revision |  Significant  |   p-value   | Median(vuln) | Median(neut) |
| -------- | ------------- | ----------- | ------------ | ------------ |
{% for r in revisions %}| {{ r.number|stringformat:"8s" }} |       {{r.page_rank.significant }}       | {{ r.page_rank.p|stringformat:"6.5e" }} | {{ r.page_rank.median.vuln|stringformat:"12.6e" }} | {{ r.page_rank.median.neut|stringformat:"12.6e" }} |
{% endfor %}

Legend
======

Significant
-----------

 Y - Metric significantly correlated with vulnerable functions.
 N - No evidence of the metric being correlated with vulnerable functions.
 X - Population of vulnerable functions with finite value for the metric not present.
