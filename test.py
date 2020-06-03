from argparse import ArgumentParser
from os import listdir
from os.path import isfile, isdir, join
import json

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

class Log:
    def __init__(self):
        self.data = None
        self.type = None
        self.name = None

    def __str__(self):
        return "Name: %s, Type: %s" % (self.name, self.type)

    def load(self, path): None

class LogXml(Log):
    def __init__(self, name):
        super().__init__()
        self.type = "XML"
        self.name = name

    def load(self, path):
        self.data = ET.ElementTree(file=path)
        self.root = self.data.getroot()

    def show(self, tag):
        for elem in self.root:
            xmlns = elem.tag.split("}")[0] + "}"
        for res in self.root.iter(xmlns+tag):
            print("{} {}: {}".format(self.name, tag, res.text))

class LogJson(Log):
    def __init__(self):
        super().__init__()

    def load(self, path):
        self.data = json.load(open(path, encoding="latin-1"))

    def show(self, tag):
        for elem in self.data:
            source = elem["_source"]
            layers = source["layers"]
            frame = layers["frame"]
            print("Wireshark frame.time: "+frame["frame.time"])


def show_tag(tree, log_type, tag):
    root = tree.getroot()
    for elem in root:
        xmlns = elem.tag.split("}")[0] + "}"
    for res in root.iter(xmlns+tag):
        print("{} {}: {}".format(log_type, tag, res.text))

def show_frame(js):
    for elem in js:
        source = elem["_source"]
        layers = source["layers"]
        frame = layers["frame"]
        print("Wireshark frame.time: "+frame["frame.time"])

def load_xml(log, path):
    if log == "Security.xml":
        res = LogXml("Security")
        res.load(path)
        res.show("EventID")
    elif log == "Sysmon.xml":
        res = LogXml("Sysmon")
        res.load(path)
        res.show("EventID")
    else:
        print("Unknown xml file name...")

def load_json(log, path):
    if log == "Wireshark.json":
        show_frame(json.load(open(path, encoding="latin-1")))
    else:
        print("Unknown json file name...")

def file_check(log, path):
    if log.endswith("xml"):
        load_xml(log, path)
    elif log.endswith("json"):
        load_json(log, path)
    else:
        print("Only for xml or json...")

def load_data(path):
    for num, file_name in enumerate(listdir(path)):
        print("testcase {}: {}".format(num+1, file_name))
        for log in listdir(join(path, file_name)):
            file_check(log, join(path, file_name, log))

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("file_path", help="root path of data")
    args = parser.parse_args()

    load_data(args.file_path)


