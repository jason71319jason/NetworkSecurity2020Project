from argparse import ArgumentParser
from os import listdir
from os.path import isfile, isdir, join
import pickle
import json
import gc
import pprint
import multiprocessing as mp

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

    def load(self): None
    def show(self, tag): None

class LogXml(Log):
    def __init__(self, name, path):
        super().__init__()
        self.type = "xml"
        self.name = name
        self.path = path

    def load(self):
        self.root = ET.ElementTree(file=self.path).getroot()

    def show(self, tag):
        for elem in self.root:
            xmlns = elem.tag.split("}")[0] + "}"
        for res in self.root.iter(xmlns+tag):
            print("{} {}: {}".format(self.name, tag, res.text))

    def show_tree(self):
        print("{}.{} Tree Structure".format(self.name, self.type))

        def elem_str(elem, depth):
            res = []
            indent = depth * "\t"
            tag = elem.tag.split("}")[1]

            if elem.text is None:
                res.append("{}<{}>".format(indent, tag))
            else:
                res.append("{}<{}> {}".format(indent, tag, elem.text))
            res.append("{}</{}>".format(indent, tag))

            return res

        def dfs(node, depth):
            for elem in node:
                print(elem_str(elem, depth)[0])
                dfs(elem, depth+1)
                print(elem_str(elem, depth)[1])


        first_event = self.root.find("./{http://schemas.microsoft.com/win/2004/08/events/event}Event")
        print(elem_str(first_event, 0)[0])
        dfs(first_event, 1)
        print(elem_str(first_event, 0)[1])

class LogJson(Log):
    def __init__(self, name, path):
        super().__init__()
        self.type = "json"
        self.name = name
        self.path = path

    def load(self):
        self.data = json.load(open(self.path, encoding="latin-1"))

    def show(self, tag):
        for elem in self.data:
            source = elem["_source"]
            layers = source["layers"]
            frame = layers["frame"]
            print("Wireshark frame.time: "+frame["frame.time"])

    def show_tree(self):
        print("{}.{} Tree Structure".format(self.name, self.type))
        pprint.pprint(self.data[0])

    def split_k_set(self, split_k_set=10):
        val_size = int(len(self.data)/10)
        upbound = len(self.data)
        start_idx = 0
        end_idx = val_size
        for i in range(split_k_set):
            train_set = self.data[:start_idx] + self.data[end_idx:]
            validation_set = self.data[start_idx:end_idx]
            start_idx += val_size
            end_idx = min(end_idx + val_size, upbound)
            yield (train_set, validation_set)

class TestCase:
    def __init__(self, name, path):
        self.path = path
        self.name = name
        self.security_log = None
        self.sysmon_log = None
        self.wireshark_log = None

    def load_xml(self, file_name):
        if file_name == "Security.xml":
            log = LogXml("Security", join(self.path, file_name))
            self.security_log = log

        elif file_name == "Sysmon.xml":
            log = LogXml("Sysmon", join(self.path, file_name))
            self.sysmon_log = log
        else:
            print("Unknown xml file name...")

    def load_json(self, file_name):
        if file_name == "Wireshark.json":
            log = LogJson("Wireshark", join(self.path, file_name))
            self.wireshark_log = log
        else:
            print("Unknown json file name...")


class DataLoader:

    def __init__(self, path):
        self.path = path

    def check_ext(self, file_name, testcase):
        if file_name.endswith("xml"):
            testcase.load_xml(file_name)
        elif file_name.endswith("json"):
            testcase.load_json(file_name)
        else:
            print("Only for xml or json...")

    def load_testcase_directory(self):
        print("deprecated")
        '''
        for testcase_dir in listdir(self.path):
            self.load_testcase(testcase_dir)
        '''

    def load_testcase(self, testcase_dir):
        testcase = TestCase(testcase_dir, join(self.path, testcase_dir))

        for file_name in listdir(join(self.path, testcase_dir)):
            self.check_ext(file_name, testcase)

        '''
        # mulit-process
        p1 = mp.Process(target=testcase.wireshark_log.load(), args=())
        p1.start()
        p2 = mp.Process(target=testcase.security_log.load(), args=())
        p2.start()
        p3 = mp.Process(target=testcase.sysmon_log.load(), args=())
        p3.start()
        p1.join()
        p2.join()
        p3.join()
        '''

        return testcase

    def __iter__(self):
        for testcase in listdir(self.path):
            yield self.load_testcase(testcase)

class Statistics:
    def __init__(self): None

class WiresharkStatistics(Statistics):
    def __init__(self, data):
        self.data = data
        self.instance_count = len(data)
        self.field_count = {}
        self.layer_count = {}

        self.protocols = [
                "ntp",
                "dhcp",
                "dhcpv6",
                "ipv6",
                "http",
                "arp",
                "nbns",
                "dns",
                "data",
                "udp",
                "tcp.segments",
                "tls",
                "tcp",
                "ip",
                "frame",
                "eth"]

    def show_range(self, up_bound, low_bound):
        over_k = int(low_bound * self.instance_count)
        under_k = int(up_bound * self.instance_count)
        for field in self.sorted_field:
            if self.field_count[field] >= over_k and self.field_count[field] < under_k:
                print("{}: {:.2%}".format(field, self.field_count[field]/self.instance_count))

    def calculate(self):
        for d in self.data:
            self.add_instance(d)

    def add_instance(self, new_data):

        field_in_packet = []

        def dfs(parent, node):

            if type(node) is not dict:
                field = node + "@" + parent
                if field not in field_in_packet:
                    if field not in self.field_count:
                        self.field_count[field] = 1
                    else:
                        self.field_count[field] += 1
                    field_in_packet.append(field)
                return None

            for n in node:
                if node[n] is not None:
                    dfs(n, node[n])

        for layer in new_data['_source']['layers']:
            if layer in self.protocols:
                dfs("layers", new_data['_source']['layers'][layer])

    def countLayers(self):
        for d in self.data:
            self.addLayer(d)

    def addLayer(self, data):
        for layer in data['_source']['layers']:
            if layer in self.layer_count:
                self.layer_count[layer] += 1
            else:
                self.layer_count[layer] = 1

class SecurityStatistics(Statistics):
    def __init__(self):
        print("Not Yet")

class SysmonStatistics(Statistics):
    def __init__(self):
        print("Not Yet")

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("-f","--file_path", help="root path of data")
    args = parser.parse_args()

    dataLoader = DataLoader(args.file_path)

    '''
    # Show fields
    total_field_count = {}
    total_packet = 0

    for num, testcase in enumerate(dataLoader):
        testcase.wireshark_log.load()
        ws = WiresharkStatistics(testcase.wireshark_log.data)
        ws.calculate()
        with open('wireshark_log/' + testcase.name + '.fields', 'w') as f:
            for field in sorted(ws.field_count.items(), key=lambda v:v[1]):
                f.write("{:>15}:{:>10}:{:>10.2%}\n".format(
                    field[0], field[1],
                    field[1]/len(ws.data)))

                if field[0] in total_field_count:
                    total_field_count[field[0]] += field[1]
                else:
                    total_field_count[field[0]] = field[1]

            total_packet += len(ws.data)

    with open('wireshark_log/total.fields', 'w') as f:
        for field in sorted(total_field_count.items(), key=lambda v:v[1]):
                f.write("{:>15}:{:>10}:{:>10.2%}\n".format(
                    field[0], field[1],
                    field[1]/len(ws.data)))

    '''
    '''
    # Show layers
    total_layer_count = {}
    total_packet = 0
    for num, testcase in enumerate(dataLoader):
        testcase.wireshark_log.load()
        ws = WiresharkStatistics(testcase.wireshark_log.data)
        ws.countLayers()
        with open('wireshark_log/' + testcase.name + '.layers', 'w') as f:
            for layer in ws.layer_count:
                f.write("{:>15}:{:>10}:{:>10.2%}\n".format(
                    layer, ws.layer_count[layer],
                    ws.layer_count[layer]/len(ws.data)))

                if layer in total_layer_count:
                    total_layer_count[layer] += ws.layer_count[layer]
                else:
                    total_layer_count[layer] = ws.layer_count[layer]

            total_packet += len(ws.data)

    with open('wireshark_log/total.layers', 'w') as f:
        for layer in sorted(total_layer_count.items(), key=lambda v:v[1]):
            f.write("{:>15}:{:>10}:{:>10.2%}\n".format(
                layer[0], layer[1],
                layer[1]/total_packet))

    '''

    '''
    # Split data
    fields = []
    for num, testcase in enumerate(dataLoader):
        testcase.wireshark_log.load()
        k = 0
        for train, val in testcase.wireshark_log.split_k_set():
            with open('set/' + str(num) + '/wireshark_' + str(k) + '.train', 'wb') as t:
                pickle.dump(train, t)
            with open('set/' + str(num) + '/wireshark_' + str(k) + '.val', 'wb') as v:
                pickle.dump(val, v)
            k += 1
        #print("testcase {}: {}".format(num+1, testcase.name))
        #ws = WiresharkStatistics(testcase.wireshark_log.data)
        #ws.calculate()
        #ws.show_range(1.25, -1)
        gc.collect()
    '''
