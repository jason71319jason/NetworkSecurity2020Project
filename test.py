from argparse import ArgumentParser
from os import listdir
from os.path import isfile, isdir, join
import json
try:
	import xml.etree.cElementTree as ET
except ImportError:
	import xml.etree.ElementTree as ET


if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument("filePath", help="root path of data")
	args = parser.parse_args()
	
	folders = listdir(args.filePath)
	num = 1
	for f in folders:
		dataPath = join(args.filePath, f)
		print("testcase %d: %s" % (num, f))
		num += 1
		data = listdir(dataPath)
		for d in data:
			fullPath = join(dataPath, d)
			fileCheck = d.split(".")
			if fileCheck[len(fileCheck)-1] == "xml":
				#print(d+" : xml")
				if fileCheck[0] == "Security":
					xmlTree = ET.ElementTree(file=fullPath)
					root = xmlTree.getroot()
					for elem in root:
						xmlns = elem.tag.split("}")[0] + "}"
					for eventId in root.iter(xmlns+"EventID"):
						print("Security EventID: "+eventId.text)
				elif fileCheck[0] == "Sysmon":
					xmlTree = ET.ElementTree(file=fullPath)
					root = xmlTree.getroot()
					for elem in root:
						xmlns = elem.tag.split("}")[0] + "}"
					for eventId in root.iter(xmlns+"EventID"):
						print("Sysmon EventID: "+eventId.text)
				else:
					print("Unknown xml file name...")
			elif fileCheck[len(fileCheck)-1] == "json":
				#print(d+" : json")
				if fileCheck[0] == "Wireshark":
					inputFile = open(fullPath, encoding="latin-1")
					jsonData = json.load(inputFile)
					for elem in jsonData:
						source = elem["_source"]
						layers = source["layers"]
						frame = layers["frame"]
						print("Wireshark frame.time: "+frame["frame.time"])
				else:
					print("Unknown json file name...")
			else:
				print("Only for xml or json...")
			#print(d)