# Name of column that splits the population into two
SWITCH = 'is_vulnerable'

# Name of control column
CONTROL = 'sloc'

# Query to get all function for a specific revision
BASE_SQL = '''
    SELECT is_vulnerable,
        sloc,
        proximity_to_entry, proximity_to_exit,
        proximity_to_defense, proximity_to_dangerous,
        page_rank
    FROM app_function
    WHERE revision_id = {0}
'''
MODELING_SQL = '''
    {0}
    AND sloc IS NOT NULL
'''.format(BASE_SQL)
TRACKING_SQL = '''
    SELECT before.name, before.file,
           before.number AS brelease, after.number AS arelease,
           -- Page Rank
           before.page_rank AS bpage_rank,
           after.page_rank AS apage_rank,
           (after.page_rank - before.page_rank) AS delta_page_rank,
           -- Proximity to Entry
           before.proximity_to_entry AS bproximity_to_entry,
           after.proximity_to_entry AS aproximity_to_entry,
           (before.proximity_to_entry - after.proximity_to_entry)
                AS delta_proximity_to_entry,
           -- Proximity to Entry
           before.proximity_to_exit AS bproximity_to_exit,
           after.proximity_to_exit AS aproximity_to_exit,
           (before.proximity_to_exit - after.proximity_to_exit)
                AS delta_proximity_to_exit,
           before.is_vulnerable, after.is_vulnerable,
           CASE
                WHEN before.is_vulnerable = 'f' AND after.is_vulnerable = 't'
                    THEN 'introduced'
                WHEN before.is_vulnerable = 'f' AND after.is_vulnerable = 'f'
                    THEN 'still_neutral'
                WHEN before.is_vulnerable = 't' AND after.is_vulnerable = 't'
                    THEN 'still_vulnerable'
                WHEN before.is_vulnerable = 't' AND after.is_vulnerable = 'f'
                    THEN 'fixed'
           END AS transition
    FROM (app_function INNER JOIN app_revision
            ON app_function.revision_id = app_revision.id) AS before,
         (app_function INNER JOIN app_revision
            ON app_function.revision_id = app_revision.id) AS after
    WHERE before.name = after.name
      AND before.file = after.file
      AND before.is_loaded = 't'
      AND after.is_loaded = 't'
      AND before.revision_id = (after.revision_id - 1)
      AND before.subject_id = {0}
      AND after.subject_id = {0}
'''

# Combination of features
FEATURE_SETS = [
    ["proximity_to_entry"],
    ["proximity_to_exit"],
    ["proximity_to_dangerous"],
    ["page_rank"],
    [
        "page_rank",
        "proximity_to_entry", "proximity_to_exit", "proximity_to_dangerous"
    ]
    ["proximity_to_defense"],
    ["page_rank", "proximity_to_defense"],
    ["page_rank", "proximity_to_defense", "proximity_to_dangerous"],
]
TRACKING_SETS = [
    (
        "page_rank",
        ["introduced"], ["still_neutral", "still_vulnerable", "fixed"]
    ),
    (
        "page_rank",
        ["fixed"], ["still_neutral", "still_vulnerable", "introduced"]
    ),
    (
        "page_rank",
        ["introduced"], ["still_neutral"]
    ),
    (
        "page_rank",
        ["fixed"], ["still_vulnerable"]
    ),
    (
        "proximity_to_entry",
        ["introduced"], ["still_neutral", "still_vulnerable", "fixed"]
    ),
    (
        "proximity_to_entry",
        ["fixed"], ["still_neutral", "still_vulnerable", "introduced"]
    ),
    (
        "proximity_to_entry",
        ["introduced"], ["still_neutral"]
    ),
    (
        "proximity_to_entry",
        ["fixed"], ["still_vulnerable"]
    ),
    (
        "proximity_to_exit",
        ["introduced"], ["still_neutral", "still_vulnerable", "fixed"]
    ),
    (
        "proximity_to_exit",
        ["fixed"], ["still_neutral", "still_vulnerable", "introduced"]
    ),
    (
        "proximity_to_exit",
        ["introduced"], ["still_neutral"]
    ),
    (
        "proximity_to_exit",
        ["fixed"], ["still_vulnerable"]
    )
]
