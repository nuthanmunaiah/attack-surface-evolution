import re

RT_DES = 'des'
RT_DES_ONE = 'des_one'
RT_DES_TWO = 'des_two'
RT_ANC = 'anc'

REACHABILITY_TYPE = (
    (RT_DES, 'Descendants'),
    (RT_ANC, 'Ancestors'),
    (RT_DES_ONE, 'Descendants at alpha = 1'),
    (RT_DES_TWO, 'Descendants at alpha = 2'),
)

RT_BRANCH = 'b'
RT_TAG = 't'

REVISION_TYPE = (
    (RT_BRANCH, 'Branch'),
    (RT_TAG, 'Tag')
)

CALLGRAPH_FILE_PATTERN = '%s_%s_%s.txt'

RE_REV_NUM = re.compile('(\d+)(?:\.(\d+))?(?:\.(\d+))?')
RE_FUNC_AFFECTED = re.compile('(\w*)(?:\s?\()')