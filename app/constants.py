import re

RT_BRANCH = 'b'
RT_TAG = 't'

REVISION_TYPE = (
    (RT_BRANCH, 'Branch'),
    (RT_TAG, 'Tag')
)

CALLGRAPH_FILE_PATTERN = '%s_%s_%s.txt'

RE_REV_NUM = re.compile('(\d+)(?:\.(\d+))?(?:\.(\d+))?')
RE_FUNC_AFFECTED = re.compile('(\w*)(?:\s?\()')