import re

RT_EPR = 'epr'
RT_EXPR = 'expr'
RT_SEPR = 'sepr'

REACHABILITY_TYPE = (
    (RT_EPR, 'Entry Point Reachability'),
    (RT_EXPR, 'Exit Point Reachability'),
    (RT_SEPR, 'Shallow Entry Point Reachability'),
)

RT_BRANCH = 'b'
RT_TAG = 't'

REVISION_TYPE = (
    (RT_BRANCH, 'Branch'),
    (RT_TAG, 'Tag')
)

CALLGRAPH_FILE_PATTERN = '%s_%s_%s.txt'

RE_REV_NUM = re.compile('(\d+)(?:\.(\d+))?(?:\.(\d+))?')
# TODO: Review return types used here
RE_FUNC_AFFECTED = re.compile('^(@@.*@@ .*(void|int)\s)(\w*)(\(.*)$')