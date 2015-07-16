import re

RT_EN = 'en'
RT_EX = 'ex'

REACHABILITY_TYPE = (
    (RT_EN, 'Entry Point Reachability'),
    (RT_EX, 'Exit Point Reachability'),
)

RT_BRANCH = 'b'
RT_TAG = 't'

REVISION_TYPE = (
    (RT_BRANCH, 'Branch'),
    (RT_TAG, 'Tag')
)

CALLGRAPH_FILE_PATTERN = '%s_%s_%s.txt'
FUNC_SLOC_FILE_PATTERN = '%s.ffmpeg.csv'

RE_REV_NUM = re.compile('(\d+)(?:[\._](\d+))?(?:[\.\_](\d+))?')
