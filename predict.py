from argparse import ArgumentParser
from os import listdir
from os.path import isfile, isdir, join
import pickle
import json
import gc
import pprint
import multiprocessing as mp
import xlwings as xw
from xlwings import Range, constants
import operator
import random
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

		# mulit-process
		#p1 = mp.Process(target=testcase.wireshark_log.load(), args=())
		#p1.start()
		#p2 = mp.Process(target=testcase.security_log.load(), args=())
		#p2.start()
		#p3 = mp.Process(target=testcase.sysmon_log.load(), args=())
		#p3.start()
		#p1.join()
		#p2.join()
		#p3.join()

		return testcase

	def __iter__(self):
		for testcase in listdir(self.path):
			yield self.load_testcase(testcase)

class Predictor:
	def __init__(self): None
	def load(self, directory): None
	def predict(self, log): None

class WiresharkPredictor(Predictor):
	def __init__(self):
		self.protocol_field = {}
		self.observed_protocol_field = {
				"http": ["http.host"],
				"dns": ["dns.qry.name","dns.resp.name"],
				"ip":["ip.src","ip.dst"]}

	def load(self, directory):
		for csv in listdir(directory):
			with open(join(directory, csv), 'r') as f:
				for l in f:
					arr = l.split(',')
					if arr[0] in self.protocol_field:
						print("Duplicate header")
					self.protocol_field[arr[0]] = arr[1:-1]

	def predict(self, data):
		field_count = self.extract(data)

		score = [0] * 6

		for field in field_count:
			if field in self.protocol_field:
				for i in range(len(self.protocol_field[field])):
					score[i] += int(self.protocol_field[field][i])

		max_val = 0
		res_idx = 1
		for i in range(6):
			if max_val < score[i]:
				res_idx = i + 1
				max_val = score[i]
		#print(max_val)
		return res_idx


	def extract(self, data):

		field_count = {}

		def extract_single(d):
			for proto in self.observed_protocol_field:
				if proto in d['_source']['layers']:
					field_count[proto] = 1
					for field in self.observed_protocol_field[proto]:
						if field in d['_source']['layers'][proto]:
							key = d['_source']['layers'][proto][field] + '@' + field
							field_count[key] = 1

		for d in data:
			extract_single(d)

		return field_count

class SecurityPredictor(Predictor):
	def __init__(self):
		self.sheet = None

	def load(self, directory):
		workbook = xw.Book(directory)
		sheet = workbook.sheets["Security"]
		self.sheet = sheet
		
	def compute(self, target, start, end):
		pred = [0, 0]
		for i in range(start, end):
			#print(self.sheet.cells(i, 'A').value)
			if self.sheet.cells(i, 'A').value == target:
				tmpMax = 0
				for j in range(2, 8):
					#print(self.sheet.cells(i, j).value)
					if self.sheet.cells(i, j).value > tmpMax:
						tmpMax = self.sheet.cells(i, j).value
						#print(tmpMax)
						pred = [j-1, tmpMax/self.sheet.cells(i, 8).value]
				break
		return pred
		
	def predict(self, data):
		for elem in data:
			xmlns = elem.tag.split("}")[0] + "}"
		dicProcessID = {}
		dicEventID = {}
		dicTask = {}
		for res in data.iter(xmlns+"Execution"):
			tmpDic = {res.attrib['ProcessID'] : 1}
			if res.attrib['ProcessID'] in dicProcessID:
				dicProcessID[res.attrib['ProcessID']] +=1
			else:
				dicProcessID.update(tmpDic)
			#print(res.attrib['ProcessID'])
		for res in data.iter(xmlns+"EventID"):
			tmpDic = {res.text : 1}
			if res.text in dicEventID:
				dicEventID[res.text] +=1
			else:
				dicEventID.update(tmpDic)
		for res in data.iter(xmlns+"Task"):
			tmpDic = {res.text : 1}
			if res.text in dicTask:
				dicTask[res.text] +=1
			else:
				dicTask.update(tmpDic)
		ProcessID =  max(dicProcessID.items(), key=operator.itemgetter(1))[0]
		EventID = max(dicEventID.items(), key=operator.itemgetter(1))[0]
		Task = max(dicTask.items(), key=operator.itemgetter(1))[0]
		#print(ProcessID)
		#print(EventID)
		#print(Task)
		ProcessIDp = self.compute(float(ProcessID), 28, 34)
		EventIDp = self.compute(float(EventID), 3, 17)
		Taskp = self.compute(float(Task), 18, 27)
		#print(ProcessIDp)
		#print(EventIDp)
		#print(Taskp)
		resList = ProcessIDp + EventIDp + Taskp
		maxP = max(resList[1::2])
		#print(maxP)
		idx = [i for i, j in enumerate(resList[1::2]) if j == maxP][0]*2
		#print(idx)
		res = resList[idx]
		return res
		
class SysmonPredictor(Predictor):
	def __init__(self):
		self.sheet = None

	def load(self, directory):
		workbook = xw.Book(directory)
		sheet = workbook.sheets["Sysmon"]
		self.sheet = sheet
		
	def compute(self, target, start, end):
		pred = [0, 0]
		for i in range(start, end):
			#print(self.sheet.cells(i, 'A').value)
			if self.sheet.cells(i, 'A').value == target:
				tmpMax = 0
				for j in range(2, 8):
					#print(self.sheet.cells(i, j).value)
					if self.sheet.cells(i, j).value > tmpMax:
						tmpMax = self.sheet.cells(i, j).value
						#print(tmpMax)
						pred = [j-1, tmpMax/self.sheet.cells(i, 8).value]
				break
		return pred
		
	def predict(self, data):
		for elem in data:
			xmlns = elem.tag.split("}")[0] + "}"
		dicProcessID = {}
		dicEventID = {}
		dicTask = {}
		for res in data.iter(xmlns+"Execution"):
			tmpDic = {res.attrib['ProcessID'] : 1}
			if res.attrib['ProcessID'] in dicProcessID:
				dicProcessID[res.attrib['ProcessID']] +=1
			else:
				dicProcessID.update(tmpDic)
			#print(res.attrib['ProcessID'])
		for res in data.iter(xmlns+"EventID"):
			tmpDic = {res.text : 1}
			if res.text in dicEventID:
				dicEventID[res.text] +=1
			else:
				dicEventID.update(tmpDic)
		for res in data.iter(xmlns+"Task"):
			tmpDic = {res.text : 1}
			if res.text in dicTask:
				dicTask[res.text] +=1
			else:
				dicTask.update(tmpDic)
		ProcessID =  max(dicProcessID.items(), key=operator.itemgetter(1))[0]
		EventID = max(dicEventID.items(), key=operator.itemgetter(1))[0]
		Task = max(dicTask.items(), key=operator.itemgetter(1))[0]
		#print(ProcessID)
		#print(EventID)
		#print(Task)
		ProcessIDp = self.compute(float(ProcessID), 25, 31)
		EventIDp = self.compute(float(EventID), 3, 13)
		Taskp = self.compute(float(Task), 14, 24)
		#print(ProcessIDp)
		#print(EventIDp)
		#print(Taskp)
		resList = ProcessIDp + EventIDp + Taskp
		maxP = max(resList[1::2])
		#print(maxP)
		idx = [i for i, j in enumerate(resList[1::2]) if j == maxP][0]*2
		#print(idx)
		res = resList[idx]
		return res

if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument("file_path", help="root path of data")
	args = parser.parse_args()

	dataLoader = DataLoader(args.file_path)

	for num, testcase in enumerate(dataLoader):
		testcase.wireshark_log.load()
		wireshark_predictor = WiresharkPredictor()
		wireshark_predictor.load('field_value_dict')
		testcase.security_log.load()
		security_predictor = SecurityPredictor()
		security_predictor.load('statistics.xlsx')
		testcase.sysmon_log.load()
		sysmon_predictor = SysmonPredictor()
		sysmon_predictor.load('statistics.xlsx')
		res1 = wireshark_predictor.predict(testcase.wireshark_log.data)
		res2 = security_predictor.predict(testcase.security_log.root)
		res3 = sysmon_predictor.predict(testcase.sysmon_log.root)
		#print("res1: {}, res2: {}, res3: {}".format(res1, res2, res3))
		resList = [res1, res2, res3]
		poll = [0]*6
		for i in range(len(resList)):
			poll[resList[i]-1] +=1
		maxNum = max(poll)
		res = [i+1 for i,x in enumerate(poll) if x==maxNum]
		#print(random.choice(res))
		print("testcase {}: person {}".format(num+1, random.choice(res)))
