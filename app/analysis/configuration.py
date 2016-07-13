# Name of column that splits the population into two
SWITCH = 'becomes_vulnerable'

# Name of control column
CONTROL = 'sloc'

# Query to get all function for a specific revision
BASE_SQL = '''
    SELECT becomes_vulnerable,
        sloc, fan_in, fan_out,
        proximity_to_entry, proximity_to_exit,
        proximity_to_defense, proximity_to_dangerous,
        page_rank
    FROM function
    WHERE release_id = {0}
'''
MODELING_SQL = '''
    {0}
    AND sloc IS NOT NULL
'''.format(BASE_SQL)

# Combination of features
FEATURE_SETS = [
    ["proximity_to_entry"],
    ["proximity_to_exit"],
    ["proximity_to_dangerous"],
    ["page_rank"],
    ["fan_in"],
    ["fan_out"],
    ["page_rank", "fan_in"],
    [
        "page_rank",
        "proximity_to_entry", "proximity_to_exit", "proximity_to_dangerous"
    ],
    ["proximity_to_defense"],
    ["page_rank", "proximity_to_defense"],
    ["page_rank", "proximity_to_defense", "proximity_to_dangerous"],
]
