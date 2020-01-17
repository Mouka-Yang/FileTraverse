import os
import csv
import re
from collections import defaultdict

UNKNOWN_EXT = "?"
FIELD_NAMES = ["name", "path", "createtime", "writetime", "readtime"]
USER_DIRS = ['desktop', 'documents', 'music',
             'videos', 'pictures', 'downloads']
USER_DIR_REEXP = r'^c:\\users\\.*?\\([^\\]+)(\\.*)*'
DOC_REEXP = r'c:\\users\\.*?\\documents\\'
DL_REEXP = r'c:\\users\\.*?\\downloads\\'
MUSIC_REEXP = r'c:\\users\\.*?\\music\\'
VIDEO_REEXP = r'c:\\users\\.*?\\videos\\'
PIC_REEXP = r'c:\\users\\.*?\\pictures'
DESKTOP_REEXP = r'c:\\users\\.*?\\desktop'

# Get file extension


def GetExtension(filename: str) -> str:
    filepart = filename.split(".")
    if len(filepart) > 1:
        # last part of the filename as it's ext
        return filepart[-1]
    else:
        # file has no ext
        return UNKNOWN_EXT


def GetScriptDirectory():
    return os.path.dirname(os.path.abspath(__file__))


def GetResultFiles(type="", path=".") -> str:
    if len(type) > 0:
        type += ".csv"

    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file() and entry.name.endswith(type):
                yield entry.path


def GetFileDirType(filename: str) -> str:
    match = re.match(USER_DIR_REEXP, filename, re.IGNORECASE)
    if match is not None and match.group(1) in USER_DIRS:
        return match.group(1)
    else:
        return 'else'


def ProcessUserResultFile(filename)-> None:
    extCount = {
        'desktop': defaultdict(int),
        'documents': defaultdict(int),
        'downloads': defaultdict(int),
        'images': defaultdict(int),
        'pictures': defaultdict(int),
        'music': defaultdict(int),
        'else': defaultdict(int),
        'total': 0
    }

    with open(filename, encoding="utf8", newline="") as infile:
        reader = csv.DictReader(infile, fieldnames=FIELD_NAMES, delimiter='|')
        for record in reader:
            ext = GetExtension(record['name'])
            dirType = GetFileDirType(record['path'].lower())
            extCount[dirType][ext] += 1
            extCount['total'] += 1

    for type in extCount.keys():
        if type is not 'total':
            sortedCount = extCount[type]
            sortedCount = sorted(sortedCount.items(),
                                 key=lambda item: item[1], reverse=True)
            sortedCount = dict(sortedCount[:10])
            extCount[type] = sortedCount

        print(type + ": ")
        print(extCount[type])


resultDir = os.path.join(GetScriptDirectory(), "result")

for file in GetResultFiles('user', resultDir):
    print(file)
    ProcessUserResultFile(file)
    break
