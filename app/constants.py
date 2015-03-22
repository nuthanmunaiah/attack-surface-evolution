import re

RT_EN = 'en'
RT_SHEN_ONE = 'shen_one'
RT_SHEN_TWO = 'shen_two'
RT_EX = 'ex'

REACHABILITY_TYPE = (
    (RT_EN, 'Entry Point Reachability'),
    (RT_EX, 'Exit Point Reachability'),
    (RT_SHEN_ONE, 'Shallow Entry Point Reachability (Alpha = 1)'),
    (RT_SHEN_TWO, 'Shallow Entry Point Reachability (Alpha = 2)'),
)

RT_BRANCH = 'b'
RT_TAG = 't'

REVISION_TYPE = (
    (RT_BRANCH, 'Branch'),
    (RT_TAG, 'Tag')
)

CALLGRAPH_FILE_PATTERN = '%s_%s_%s.txt'
FUNC_SLOC_FILE_PATTERN = '%s.ffmpeg.csv'

RE_REV_NUM = re.compile('(\d+)(?:\.(\d+))?(?:\.(\d+))?')
