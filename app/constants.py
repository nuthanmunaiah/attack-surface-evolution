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

SUBJECTS = {
        'ffmpeg': 'https://github.com/ffmpeg/ffmpeg',
        'wireshark': 'https://github.com/wireshark/wireshark',
    }

ASSETS_ROOT_URL = (
    'https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.googledrive.com/host/0B1'
    'eWsh8KZjRrfjg0Z1VkcU96U2hQal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0'
)
