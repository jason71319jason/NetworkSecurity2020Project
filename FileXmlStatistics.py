from argparse import ArgumentParser
from os import listdir
from os.path import isfile, isdir, join
import json
import gc
import pprint
import multiprocessing as mp
import threading as td
import xlwings as xw
from xlwings import Range, constants
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
	
	def statistics(self, tag):
		for elem in self.root:
			xmlns = elem.tag.split("}")[0] + "}"
		dic = {}
		if tag == "Execution":
			for res in self.root.iter(xmlns+tag):
				tmpDic = {res.attrib['ProcessID'] : 1}
				if res.attrib['ProcessID'] in dic:
					dic[res.attrib['ProcessID']] +=1
				else:
					dic.update(tmpDic)
				#print(res.attrib['ProcessID'])
		else:
			for res in self.root.iter(xmlns+tag):
				tmpDic = {res.text : 1}
				if res.text in dic:
					dic[res.text] +=1
				else:
					dic.update(tmpDic)
		return dic
		
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

'''class LogJson(Log):
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
		pprint.pprint(self.data[0])'''

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

	'''def load_json(self, file_name):
		if file_name == "Wireshark.json":
			log = LogJson("Wireshark", join(self.path, file_name))
			self.wireshark_log = log
		else:
			print("Unknown json file name...")'''


class DataLoader:

	def __init__(self, path):
		self.path = path

	def check_ext(self, file_name, testcase):
		if file_name.endswith("xml"):
			testcase.load_xml(file_name)
		'''elif file_name.endswith("json"):
			testcase.load_json(file_name)
		else:
			print("Only for xml or json...")'''

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
		p2 = mp.Process(target=testcase.security_log.load(), args=())
		p2.start()
		p3 = mp.Process(target=testcase.sysmon_log.load(), args=())
		p3.start()
		#p1.join()
		p2.join()
		p3.join()

		return testcase

	def __iter__(self):
		for testcase in listdir(self.path):
			yield self.load_testcase(testcase)
	 
def mergeDict(dict1, dict2, length):
	dict3 = {**dict2, **dict1}
	for key, value in dict3.items():
		if key in dict1 and key in dict2:
			value = [value] if not isinstance(value, list) else value
			value2 = dict2[key]
			value2 = [value2] if not isinstance(value2, list) else value2
			dict3[key] = value + value2
		elif key in dict1 and key not in dict2:
			value = [value] if not isinstance(value, list) else value
			dict3[key] = value + [0]
		elif key not in dict1 and key in dict2:
			value2 = dict2[key]
			value2 = [value2] if not isinstance(value2, list) else value2
			tmpList = [0]*length
			dict3[key] = tmpList + value2
			
	return dict3

def fillSheet(sheetName, tag, dic):
	sheet = workbook.sheets[sheetName]
	empty = sheet.range('A' + str(sheet.cells.last_cell.row)).end('up').row+1
	if tag == "Execution":
		sheet.cells(empty, 'A').value = "ProcessID"
	else:
		sheet.cells(empty, 'A').value = tag
	for i in range(2, 8):
		sheet.cells(empty, i).value = "Person"+str(i-1)
	empty += 1
	for key in dic:
		sheet.cells(empty, 1).value = key
		for i in range(6):
			sheet.cells(empty, i+2).value = dic[key][i]
		empty += 1
if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument("file_path", help="root path of data")
	parser.add_argument("tag", help="tag of xml")
	args = parser.parse_args()

	dataLoader = DataLoader(args.file_path)
	workbook = xw.Book('statistics.xlsx')
	sheetNameList = [sh.name for sh in workbook.sheets]
	if 'Sysmon' not in sheetNameList:
		workbook.sheets.add('Sysmon')
	if 'Security' not in sheetNameList:
		workbook.sheets.add('Security')
	securityDic = {}
	sysmonDic = {}
	for num, testcase in enumerate(dataLoader):
		print("testcase {}: {}".format(num+1, testcase.name))
		#testcase.wireshark_log.show("frame.time")
		dict2 = testcase.sysmon_log.statistics(args.tag)
		dict3 = mergeDict(sysmonDic, dict2, num)
		sysmonDic = dict3
		#print("sysmonDic: {}".format(sysmonDic))
		dict2 = testcase.security_log.statistics(args.tag)
		dict3 = mergeDict(securityDic, dict2, num)
		securityDic = dict3
		#print("securityDic: {}".format(securityDic))
	fillSheet('Sysmon', args.tag, sysmonDic)
	fillSheet('Security', args.tag, securityDic)
	