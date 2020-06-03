from argparse import ArgumentParser
from os import listdir
from os.path import isfile, isdir, join
import json

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

def show_eventID(xmlTree, log_type):
    root = xmlTree.getroot()
    for elem in root:
        xmlns = elem.tag.split("}")[0] + "}"
    for eventId in root.iter(xmlns+"EventID"):
        print("{} EventID: {}".format(log_type, eventId.text))

def load_xml(log, full_path):
    if log == "Security.xml":
        show_eventID(ET.ElementTree(file=full_path), "Security")
    elif log == "Sysmon.xml":
        show_eventID(ET.ElementTree(file=full_path), "Sysmon")
    else:
        print("Unknown xml file name...")

def load_json(log, full_path):
    if log == "Wireshark.json":
        for elem in json.load(open(full_path, encoding="latin-1")):
            source = elem["_source"]
            layers = source["layers"]
            frame = layers["frame"]
            print("Wireshark frame.time: "+frame["frame.time"])
    else:
        print("Unknown json file name...")

def file_check(log, full_path):
    if log.endswith("xml"):
        load_xml(log, full_path)
    elif log.endswith("json"):
        load_json(log, full_path)
    else:
        print("Only for xml or json...")

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("file_path", help="root path of data")
    args = parser.parse_args()

    for num, testcase in enumerate(listdir(args.file_path)):
        print("testcase {}: {}".format(num+1, testcase))
        for log in listdir(join(args.file_path, testcase)):
            file_check(log, join(args.file_path, testcase, log))

