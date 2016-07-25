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
    FROM {table}
    WHERE release_id = {release}
'''
