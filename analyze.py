from os import chdir, makedirs, name, walk
from os.path import abspath, basename, dirname, isdir, isfile, islink, join, split, splitdrive, splitext
from sys import argv, exit
from ast import literal_eval
from getpass import getpass
from io import BytesIO
from time import sleep
from zipfile import ZipFile
try:
	chdir(abspath(dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)


class Parser:
	__OptionDelimiter = ("//", "--")
	__OptionHelp = ("h", "/h", "-h", "help", "/help", "--help")
	__OptionOutput = ("o", "/o", "-o", "output", "/output", "--output")
	__DefaultOutput = "%p/%nFigures"
	__OptionPlace = ("p", "/p", "-p", "place", "/place", "--place")
	__DefaultPlace = 9
	__PlaceTranslations = {"s":0, "second":0, "ms":3, "millisecond":3, "microsecond":6, "ns":9, "nanosecond":9, "ps":12, "picosecond":12, "fs":15, "femtosecond":15}
	__OptionTime = ("t", "/t", "-t", "time", "/time", "--time")
	__OptionUnit = ("u", "/u", "-u", "unit", "/unit", "--unit")
	__DefaultTime = float("inf")
	__tcgetattr = None
	__OriginalConsoleAttributes = None
	__ECHOLESSNESS = None
	__EcholessConsoleAttributes = None
	__tcsetattr = None
	@staticmethod
	def __formatOption(option:tuple|list, pre:str = "[", sep:str = "|", suf:str = "]") -> str:
		if isinstance(option, (tuple, list)) and all(isinstance(op, str) for op in option):
			prefix = pre if isinstance(pre, str) else "["
			separator = sep if isinstance(sep, str) else "|"
			suffix = suf if isinstance(suf, str) else "]"
			return prefix + separator.join(option) + suffix
		else:
			return ""
	@staticmethod
	def __printHelp() -> None:
		print("This is the official cryptographic scheme performance analyzer. ")
		print()
		print("Options (case-insensitive): ")
		print("\t{0}\t\tIndicate that all the following arguments are independent input paths. ".format(Parser.__formatOption(Parser.__OptionDelimiter)))
		print("\t{0}\t\tPrint this help document. ".format(Parser.__formatOption(Parser.__OptionHelp)))
		print((
			"\t{0} <output>\t\tSpecify the output file path without an extension, which can be a format string, "
			+ "where %%, %d, %n, %p, %x stand for the %, Drive letter (if applicable), main file Name, directory Path, and eXtension, respectively. The default value is {1}. "
		).format(Parser.__formatOption(Parser.__OptionOutput), repr(Parser.__DefaultOutput)))
		print("\t{0} [s|ms|microsecond|ns|ps|0|3|6|9|12|...]\t\tSpecify the decimal place, which should be a non-negative integer. The default value is {1}. ".format(
			Parser.__formatOption(Parser.__OptionPlace), Parser.__DefaultPlace
		))
		print(
			"\t{0} [0|0.1|1|10|...|inf]\t\tSpecify the waiting time before exiting, which should be non-negative. ".format(Parser.__formatOption(Parser.__OptionTime))
			+ "Passing inf requires users to manually press the Enter key before exiting. The default value is {0}. ".format(Parser.__DefaultTime)
		)
		print((
			"\t{0}\t\tSpecify a processing unit using a Python dictionary containing the keys \"i\" and \"o\", "
			+ "in which the value for \"i\" can be a string, a tuple, or a list, and the value for \"o\" should be a string. "
		).format(Parser.__formatOption(Parser.__OptionUnit)))
		print()
	@staticmethod
	def __parseRealNumber(string:str) -> int|float|None:
		try:
			realNumberString = "".join(character for character in string if character in "+-." or character.isalnum()).lower()
			if "x" not in realNumberString and "e" in realNumberString and not realNumberString.endswith("e"):
				return float(realNumberString)
			else:
				minusSign = False
				while realNumberString:
					if '+' == realNumberString[0]:
						realNumberString = realNumberString[1:]
					elif '-' == realNumberString[0]:
						minusSign, realNumberString = not minusSign, realNumberString[1:]
					else:
						break
				realNumberString = realNumberString.lstrip("0")
				if realNumberString.startswith("b"):
					base, digits, realNumberString = 2, "01", realNumberString[1:]
				elif realNumberString.startswith("q"):
					base, digits, realNumberString = 4, "0123", realNumberString[1:]
				elif realNumberString.startswith("o"):
					base, digits, realNumberString = 8, "01234567", realNumberString[1:]
				elif realNumberString.startswith(("d", "l")):
					base, digits, realNumberString = 10, "0123456789", realNumberString[1:]
				elif realNumberString.startswith(("h", "x")):
					base, digits, realNumberString = 16, "0123456789abcdef", realNumberString[1:]
				elif realNumberString.endswith("b"):
					base, digits, realNumberString = 2, "01", realNumberString[:-1]
				elif realNumberString.endswith("q"):
					base, digits, realNumberString = 4, "0123", realNumberString[:-1]
				elif realNumberString.endswith("o"):
					base, digits, realNumberString = 8, "01234567", realNumberString[:-1]
				elif realNumberString.endswith(("d", "l")):
					base, digits, realNumberString = 10, "0123456789", realNumberString[:-1]
				elif realNumberString.endswith(("h", "x")):
					base, digits, realNumberString = 16, "0123456789abcdef", realNumberString[:-1]
				else:
					base, digits = 10, "0123456789"
				if "inf" == realNumberString:
					realNumber = float("inf")
				elif "nan" == realNumberString:
					realNumber = float("nan")
				else:
					integerPartString, decimalPartString = realNumberString.split(".")[:2] if "." in realNumberString else (realNumberString, "")
					realNumber = 0
					for character in reversed(decimalPartString.rstrip("0")):
						realNumber += digits.index(character)
						realNumber /= base
					integerPartString = integerPartString.lstrip("0")
					if integerPartString:
						realNumber += int(integerPartString, base = base)
					if isinstance(realNumber, float) and realNumber.is_integer():
						realNumber = int(realNumber)
				if minusSign:
					realNumber = -realNumber
				return realNumber
		except:
			return None
	@staticmethod
	def parse(args:tuple|list) -> tuple:
		arguments = tuple(argument for argument in args if isinstance(argument, str)) if isinstance(args, (tuple, list)) else ()
		flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, units = max(EXIT_SUCCESS, EOF) + 1, Parser.__DefaultOutput, Parser.__DefaultPlace, Parser.__DefaultTime, []
		index, argumentCount, nonOptionMode, buffers = 1, len(arguments), False, []
		while index < argumentCount:
			argument = arguments[index].lower()
			if nonOptionMode:
				units.append(arguments[index])
			elif argument in Parser.__OptionDelimiter:
				nonOptionMode = True
			elif argument in Parser.__OptionHelp:
				Parser.__printHelp()
				flag = EXIT_SUCCESS
				break
			elif argument in Parser.__OptionOutput:
				index += 1
				if index < argumentCount:
					outputPathWithoutAnExtension = arguments[index]
				else:
					flag = EOF
					buffers.append("Parser: The value for the output path without an extension option is missing at [{0}]. ".format(index))
			elif argument in Parser.__OptionPlace:
				index += 1
				if index < argumentCount:
					decimalPlaceLower = arguments[index].lower()
					if decimalPlaceLower in Parser.__PlaceTranslations:
						decimalPlace = Parser.__PlaceTranslations[decimalPlaceLower]
					else:
						p = Parser.__parseRealNumber(arguments[index])
						if p is None:
							flag = EOF
							buffers.append("Parser: The value [{0}] = {1} for the decimal place option cannot be recognized. ".format(index, repr(arguments[index])))
						elif isinstance(p, int) and p >= 0:
							decimalPlace = p
						else:
							flag = EOF
							buffers.append("Parser: The value [{0}] = {1} for the decimal place option should be a non-negative integer. ".format(index, p))
						del p
				else:
					flag = EOF
					buffers.append("Parser: The value for the decimal place option is missing at [{0}]. ".format(index))
			elif argument in Parser.__OptionTime:
				index += 1
				if index < argumentCount:
					t = Parser.__parseRealNumber(arguments[index])
					if t is None:
						flag = EOF
						buffers.append("Parser: The type of the value [{0}] = {1} for the waiting time option is invalid. ".format(index, repr(arguments[index])))
					elif t >= 0:
						waitingTime = t
					else:
						flag = EOF
						buffers.append("Parser: The value [{0}] = {1} for the waiting time option should be a non-negative value. ".format(index, t))
					del t
				else:
					flag = EOF
					buffers.append("Parser: The value for the waiting time option is missing at [{0}]. ".format(index))
			elif argument in Parser.__OptionUnit:
				index += 1
				if index < argumentCount:
					try:
						unit = literal_eval(arguments[index])
						if isinstance(unit, dict) and "i" in unit and "o" in unit:
							units.append(unit)
						else:
							buffers.append("Parser: The value [{0}] = {1} for the unit option should be a Python dictionary containing the keys \"i\" and \"o\". ".format(
								index, repr(arguments[index])
							))
					except BaseException as e:
						buffers.append("Parser: The value [{0}] = {1} for the unit option cannot be literally evaluated due to {2}. ".format(index, repr(arguments[index]), repr(e)))
				else:
					flag = EOF
					buffers.append("Parser: The value for the unit option is missing at [{0}]. ".format(index))
			else:
				units.append(arguments[index])
			index += 1
		if EOF == flag:
			for buffer in buffers:
				print(buffer)
		return (flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, units)
	@staticmethod
	def disableConsoleEchoes() -> bool:
		if "posix" == name:
			try:
				if Parser.__tcgetattr is None:
					Parser.__tcgetattr = __import__("termios").tcgetattr
				if Parser.__OriginalConsoleAttributes is None:
					Parser.__OriginalConsoleAttributes = Parser.__tcgetattr(0)
				if Parser.__ECHOLESSNESS is None:
					Parser.__ECHOLESSNESS = ~__import__("termios").ECHO
				if Parser.__EcholessConsoleAttributes is None:
					Parser.__EcholessConsoleAttributes = Parser.__tcgetattr(0)
					Parser.__EcholessConsoleAttributes[3] &= Parser.__ECHOLESSNESS
				if Parser.__tcsetattr is None:
					Parser.__tcsetattr = __import__("termios").tcsetattr
				Parser.__tcsetattr(0, 0, Parser.__EcholessConsoleAttributes)
			except:
				return False
		return True
	@staticmethod
	def getDefaultOutput() -> str:
		return Parser.__DefaultOutput
	@staticmethod
	def restoreConsoleEchoes() -> bool:
		if "posix" == name:
			try:
				Parser.__tcsetattr(0, 0, Parser.__OriginalConsoleAttributes)
				Parser.__OriginalConsoleAttributes = None
			except:
				return False
		return True

class Loader:
	__read_csv = None
	__read_excel = None
	@staticmethod
	def load(inputFilePath:str, caseSensitive:bool = False) -> dict|BaseException: # {"x":[1, 2, 3], "y":[1, 4, 9]}
		try:
			originalExtension = splitext(inputFilePath)[1]
			extension = originalExtension.lower() if caseSensitive is not True else originalExtension
			if ".csv" == extension:
				if Loader.__read_csv is None:
					Loader.__read_csv = __import__("pandas").read_csv
				return Loader.__read_csv(inputFilePath).to_dict(orient = "list")
			elif ".tsv" == extension:
				if Loader.__read_csv is None:
					Loader.__read_csv = __import__("pandas").read_csv
				return Loader.__read_csv(inputFilePath, sep = '\t').to_dict(orient = "list")
			elif ".xlsx" == extension:
				if Loader.__read_excel is None:
					Loader.__read_excel = __import__("pandas").read_excel
				return Loader.__read_excel(inputFilePath).to_dict(orient = "list")
			else:
				return ValueError("The extension {0} is currently unsupported. ".format(repr(originalExtension)))
		except BaseException as e:
			return e

class Drawer:
	__Colors = ("blue", "red", "green", "black", "orange", "purple", "cyan", "magenta", "gray", "brown", "pink", "lime", "navy", "teal", "aqua", "maroon", "olive", "gold", "silver")
	__ColorLength = len(__Colors)
	__Markers = ("o", ".", "s", "^", "v", "x", "+", "*", "D", "d", "p", "h", "<", ">", "1", "2", "3", "4", "|", "_")
	__MarkerLength = len(__Markers) # try to make ``gcd(__ColorLength, __MarkerLength)`` equal to 1, or as small a positive integer as possible
	__plt = None
	__LabelFontSize = 14
	__LegendFontSize = 12
	@staticmethod
	def __checkValues(values:tuple|list) -> bool:
		return isinstance(values, (tuple, list)) and values and all(isinstance(value, (int, float, str)) for value in values)
	@staticmethod
	def __checkNumbers(numbers:tuple|list) -> bool:
		return isinstance(numbers, (tuple, list)) and numbers and all(isinstance(number, (int, float)) for number in numbers)
	@staticmethod
	def configure() -> bool|BaseException:
		try:
			if Drawer.__plt is None:
				from matplotlib import pyplot as plt
				Drawer.__plt = plt
				Drawer.__plt.rcParams["font.family"] = "Times New Roman"
				Drawer.__plt.rcParams["font.size"] = 12##########
				Drawer.__plt.rcParams["mathtext.fontset"] = "custom"
				Drawer.__plt.rcParams["mathtext.rm"] = "Times New Roman"
				Drawer.__plt.rcParams["mathtext.it"] = "Times New Roman:italic"
				Drawer.__plt.rcParams["mathtext.bf"] = "Times New Roman:bold"
			return True
		except BaseException as e:
			return e
	@staticmethod
	def draw(curves:tuple|list, xLabelName:str|None = None, yLabelName:str|None = None) -> bytes|BaseException:
		try:
			if isinstance(curves, (tuple, list)): # curves = ({"x":(1, 2, 3), "y":(1, 4, 9), "label":"$y = x^2$"}, {"x":(1, 2, 3), "y":(1, 8, 27), "label":"$y = x^3$"})
				for curve in curves:
					if (
						isinstance(curve, dict) and "x" in curve and Drawer.__checkNumbers(curve["x"])
						and "y" in curve and Drawer.__checkNumbers(curve["y"]) and len(curve["x"]) == len(curve["y"])
					):
						x, y = zip(*sorted(zip(curve["x"], curve["y"]))) # sort $x$ and $y$ by ascending $x$ values
						keywordArguments = {key:value for key, value in curve.items() if key in ("color", "marker", "label")}
						try:
							Drawer.__plt.plot(x, y, **keywordArguments)
						except Exception:
							Drawer.__plt.plot(x, y)
				if isinstance(xLabelName, str):
					Drawer.__plt.xlabel(xLabelName, fontsize = Drawer.__LabelFontSize)
				if isinstance(yLabelName, str):
					Drawer.__plt.ylabel(yLabelName, fontsize = Drawer.__LabelFontSize)
				_, labels = Drawer.__plt.gca().get_legend_handles_labels()
				if labels:
					Drawer.__plt.legend(loc = "best", frameon = True, fontsize = Drawer.__LegendFontSize)
				Drawer.__plt.tight_layout()
				with BytesIO() as buffer:
					Drawer.__plt.savefig(buffer, format = "pdf")
					Drawer.__plt.close()
					return buffer.getvalue()
			else:
				return TypeError("The curves should be a tuple or a list of dictionaries. ")
		except BaseException as e:
			return e
	@staticmethod
	def drawMappings(mappings:dict, independentVariables:tuple|list, dependentVariables:tuple|list, groupingVariables:tuple|list) -> dict|BaseException:
		if isinstance(mappings, dict) and all(isinstance(key, str) and Drawer.__checkValues(value) for key, value in mappings.items()) and len(set(len(value) for value in mappings.values())) == 1:
			variables = tuple(mappings.keys())
			variableLength = len(variables)
			def __getVariableName(variable:str|int) -> str: # locate variable names
				if isinstance(variable, str):
					if variable in variables:
						return variable
				elif isinstance(variable, int):
					if -variableLength <= variable and variable < variableLength:
						return variables[variable]
				return None
			independentVariableNames = []
			if isinstance(independentVariables, (tuple, list)):
				for independentVariable in independentVariables:
					variableName = __getVariableName(independentVariable)
					if isinstance(variableName, str):
						independentVariableNames.append(variableName)
			else:
				variableName = __getVariableName(independentVariables)
				if isinstance(variableName, str):
					independentVariableNames.append(variableName)
			dependentVariableNames = []
			if isinstance(dependentVariables, (tuple, list)):
				for dependentVariable in dependentVariables:
					variableName = __getVariableName(dependentVariable)
					if isinstance(variableName, str):
						dependentVariableNames.append(variableName)
			else:
				variableName = __getVariableName(dependentVariables)
				if isinstance(variableName, str):
					dependentVariableNames.append(variableName)
			groupingVariableNames = []
			if isinstance(groupingVariables, (tuple, list)):
				for groupingVariable in groupingVariables:
					variableName = __getVariableName(groupingVariable)
					if isinstance(variableName, str):
						groupingVariableNames.append(variableName)
			else:
				variableName = __getVariableName(groupingVariables)
				if isinstance(variableName, str):
					groupingVariableNames.append(variableName)
			del __getVariableName
			if independentVariableNames and dependentVariableNames and groupingVariableNames:
				seenVariableNames = set()
				for independentVariableName in independentVariableNames:
					if independentVariableName in seenVariableNames:
						return ValueError("The independent variable {0} is repeated. ".format(repr(independentVariableName)))
					else:
						seenVariableNames.add(independentVariableName)
				for dependentVariableName in dependentVariableNames:
					if dependentVariableName in seenVariableNames:
						return ValueError("The dependent variable {0} is repeated. ".format(repr(dependentVariableName)))
					else:
						seenVariableNames.add(dependentVariableName)
				for groupingVariableName in groupingVariableNames:
					if groupingVariableName in seenVariableNames:
						return ValueError("The group variable {0} is repeated. ".format(repr(groupingVariableName)))
					else:
						seenVariableNames.add(groupingVariableName)
				del seenVariableNames
				if Drawer.__plt is None:
					configurationStatus = Drawer.configure()
					if configurationStatus is not True:
						return configurationStatus
				valueLength = len(next(iter(mappings.values())))
				byteMappings = {}
				for groupingVariableName in groupingVariableNames:
					groupingVariableIndex = variables.index(groupingVariableName) # for naming purposes
					groupingVariableValues = []
					for valueIndex in range(valueLength): # start to make the color and the marker for the same group variable value the same across different figures
						if mappings[groupingVariableName][valueIndex] not in groupingVariableValues:
							groupingVariableValues.append(mappings[groupingVariableName][valueIndex])
					colors = {groupingVariableValue:Drawer.__Colors[enumerationIndex % Drawer.__ColorLength] for (
						enumerationIndex, groupingVariableValue
					) in enumerate(groupingVariableValues)}
					markers = {groupingVariableValue:Drawer.__Markers[enumerationIndex % Drawer.__MarkerLength] for (
						enumerationIndex, groupingVariableValue
					) in enumerate(groupingVariableValues)} # finish
					for independentVariableName in independentVariableNames:
						independentVariableIndex = variables.index(independentVariableName) # for naming purposes
						controlledVariableNames = tuple(
							controlledVariableName for controlledVariableName in independentVariableNames if controlledVariableName != independentVariableName
						)
						controlledVariableIndexes = tuple(variables.index(controlledVariableName) for controlledVariableName in controlledVariableNames) # for naming purposes
						valueIndexGroups = {} # start to find out all the value index groups to reduce the time complexity
						for valueIndex in range(valueLength):
							valueIndexGroups.setdefault(
								tuple(mappings[controlledVariableName][valueIndex] for controlledVariableName in controlledVariableNames), []
							).append(valueIndex) # finish
						for dependentVariableName in dependentVariableNames:
							dependentVariableIndex = variables.index(dependentVariableName) # for naming purposes
							for curveGroupIndex, valueIndexGroup in enumerate(valueIndexGroups.values()):
								curveMappings = {}
								for valueIndex in valueIndexGroup:
									groupingVariableValue = mappings[groupingVariableName][valueIndex]
									curveMappings.setdefault(groupingVariableValue, {})
									curveMappings[groupingVariableValue].setdefault(
										mappings[independentVariableName][valueIndex], []
									).append(mappings[dependentVariableName][valueIndex]) # to avoid multiple ``y`` values
								curves = []
								for outerKey, outerValue in curveMappings.items(): # groupingVariableValue -> {x -> y(s)}
									curves.append({"color":colors[outerKey], "marker":markers[outerKey], "label":outerKey})
									for innerKey, innerValue in outerValue.items(): # x -> y(s)
										if Drawer.__checkNumbers(innerValue):
											innerValueLength = len(innerValue)
											if innerValueLength >= 2:
												curves[-1].setdefault("x", []).append(innerKey)
												curves[-1].setdefault("y", []).append(sum(innerValue) / innerValueLength)
											elif 1 == innerValueLength:
												curves[-1].setdefault("x", []).append(innerKey)
												curves[-1].setdefault("y", []).append(innerValue[0])
									if not ("x" in curves[-1] and curves[-1]["x"] and "y" in curves[-1] and curves[-1]["y"]):
										del curves[-1]
								byteMappings["x{0}y{1}{2}g{3}".format(independentVariableIndex, dependentVariableIndex, "".join(
									"c{0}".format(controlledVariableIndex) for controlledVariableIndex in controlledVariableIndexes
								), curveGroupIndex)] = Drawer.draw(curves, xLabelName = independentVariableName, yLabelName = dependentVariableName)
				return byteMappings
			else:
				return ValueError("Independent, dependent and group variables should not be empty. ")
		else:
			return TypeError("The mappings should be a dictionary containing several mappings from a string to a tuple or a list of numbers. ")

class Analyzer:
	def __init__(self:object, inputFilePaths:tuple|list|str, outputFilePath:str, caseSensitive:bool = False) -> object:
		self.__inputFilePaths = inputFilePaths
		self.__outputFilePath = outputFilePath
		self.__caseSensitive = caseSensitive is True
	def __load(self:object) -> dict|BaseException:
		if isinstance(self.__inputFilePaths, (tuple, list)):
			index, length = 0, len(self.__inputFilePaths)
			while index < length:
				if isinstance(self.__inputFilePaths[index], str):
					mappings = Loader.load(self.__inputFilePaths[index], caseSensitive = self.__caseSensitive)
					if isinstance(mappings, dict):
						keys = set(mappings.keys())
						index += 1
						while index < length: # for (++index; index < length; ++index)
							currentMappings = Loader.load(self.__inputFilePaths[index], caseSensitive = self.__caseSensitive)
							if isinstance(currentMappings, dict):
								if set(currentMappings.keys()) == keys:
									for key in mappings.keys():
										mappings[key].extend(currentMappings[key])
								else:
									return KeyError("Keys mismatched across different mappings. ")
							else:
								return TypeError("Stopped loading remaining files, interrupted by {0} due to {1}. ".format(
									repr(self.__inputFilePaths[index]), repr(currentMappings)
								))
							index += 1
						return mappings
					else:
						return TypeError("Stopped loading remaining files, interrupted by {0} due to {1}. ".format(repr(self.__inputFilePaths[index]), repr(mappings)))
				index += 1
			return ValueError("No strings were found in the unit of the input file paths. ")
		elif isinstance(self.__inputFilePaths, str):
			return Loader.load(self.__inputFilePaths, caseSensitive = self.__caseSensitive)
		else:
			return TypeError("The input file path(s) should be a tuple, a list, or a string. ")
	@staticmethod
	def __checkValues(values:tuple|list) -> bool:
		return isinstance(values, (tuple, list)) and values and all(isinstance(value, (int, float, str)) for value in values)
	def analyze(self:object) -> bool|dict|BaseException:
		mappings = self.__load()
		if isinstance(mappings, BaseException):
			return IOError("Failed to load mappings from {0} due to {1}. ".format(repr(self.__inputFilePaths), repr(mappings)))
		elif isinstance(mappings, dict) and all(isinstance(key, str) and Analyzer.__checkValues(value) for key, value in mappings.items()) and len(set(len(value) for value in mappings.values())) == 1:
			variables = tuple(mappings.keys())
			if "solution" in variables:
				groupingVariableIndex = variables.index("solution")
			elif "scheme" in variables:
				groupingVariableIndex = variables.index("scheme")
			else:
				return ValueError("Failed to find a suitable group key in mappings. ")
			if "secparam" in variables:
				secparamVariableIndex = variables.index("secparam")
			else:
				return ValueError("Failed to locate the security parameter key in mappings. ")
			if "runCount" in variables:
				runCountVariableIndex = variables.index("runCount")
			else:
				return ValueError("Failed to locate the run count key in mappings. ")
			dependentVariableIndexes = tuple(variableIndex for variableIndex, variableName in enumerate(variables) if (
				variableName.endswith("(s)") or (variableName.endswith("(B)") and not variableName.startswith("elementOf"))
			))
			if dependentVariableIndexes and secparamVariableIndex < runCountVariableIndex and runCountVariableIndex < dependentVariableIndexes[0]:
				independentVariableIndexes = tuple(variableIndex for variableIndex in range(secparamVariableIndex, runCountVariableIndex) if variableIndex != groupingVariableIndex)
				validationVariableIndexes = tuple(variableIndex for variableIndex in range(runCountVariableIndex, dependentVariableIndexes[0]))
				validationVariableNames = tuple(variables[variableIndex] for variableIndex in validationVariableIndexes)
				for valueIndex in range(len(next(iter(mappings.values()))) - 1, -1, -1): # remove failed experiments
					runCountVariableValue = mappings["runCount"][valueIndex]
					for validationVariableName in validationVariableNames[1:]:
						if mappings[validationVariableName][valueIndex] != runCountVariableValue:
							break
					else: # end for naturally
						continue
					for value in mappings.values():
						value.pop(valueIndex)
				try:
					outputDirectoryPath = dirname(self.__outputFilePath)
					if outputDirectoryPath:
						makedirs(outputDirectoryPath, exist_ok = True)
					byteMappings = Drawer.drawMappings(mappings, independentVariableIndexes, dependentVariableIndexes, groupingVariableIndex)
					if isinstance(byteMappings, dict):
						__getFileExtension = (lambda x:splitext(x)[1]) if self.__caseSensitive else (lambda x:splitext(x)[1].lower())
						compressionMappings = {}
						with ZipFile(self.__outputFilePath if ".zip" == __getFileExtension(self.__outputFilePath) else self.__outputFilePath + ".zip", "w") as zf:
							for key, value in byteMappings.items():
								if isinstance(key, str) and isinstance(value, bytes):
									zf.writestr(key if ".pdf" == __getFileExtension(key) else key + ".pdf", value)
								else:
									compressionMappings[key] = value
						return compressionMappings if compressionMappings else True
					else:
						return byteMappings
				except BaseException as e:
					return e
			else:
				return ValueError("Data loaded do not contain suitable query, validator or metric variables. ")
		else:
			return ValueError("The mappings loaded are invalid. ")

class Analyzers:
	__escapeTEX = lambda x:"\\textbackslash{}".join(
		string.replace("#", "\\#").replace("$", "\\$").replace("%", "\\%").replace("&", "\\&").replace("_", "\\_").replace("{", "\\{").replace("}", "\\}")
		.replace("<", "\\textless{}").replace(">", "\\textgreater{}").replace("^", "\\textasciicircum{}").replace("~", "\\textasciitilde{}")
		for string in "".join(character for character in str(x) if ' ' <= character <= '~').split("\\")
	)#####
	__DefaultExtensions = {".csv", ".xlsx"}
	__DefaultFormatString = Parser.getDefaultOutput()
	__DefaultCompilationTimeout = 10#####
	def __init__(self:object, *units:tuple, caseSensitive:bool = False, extensions:tuple|list|set|str = __DefaultExtensions, formatString:str = __DefaultFormatString) -> object:
		self.__units = []
		self.__analyzers = []
		self.__caseSensitive = caseSensitive is True
		self.__getFileExtension = (lambda x:splitext(x)[1]) if self.__caseSensitive else (lambda x:splitext(x)[1].lower())
		if isinstance(extensions, (tuple, list, set)):
			if self.__caseSensitive:
				self.__extensions = {extension for extension in extensions if isinstance(extension, str)}
			else:
				self.__extensions = {extension.lower() for extension in extensions if isinstance(extension, str)}
		elif isinstance(extensions, str):
			self.__extensions = {extensions if self.__caseSensitive else extensions.lower()}
		else:
			self.__extensions = __DefaultExtensions
		self.__formatString = formatString if isinstance(formatString, str) else Analyzers.__DefaultFormatString
		self.updateUnits(*units if units else ".")
	def __getUnitInputFilePaths(self:object, *paths:tuple) -> tuple:
		inputFilePaths, stack = [], list(reversed(paths))
		while stack:
			element = stack.pop()
			if isinstance(element, (tuple, list)):
				stack.extend(reversed(element))
			elif isinstance(element, set):
				stack.extend(sorted(element, reverse = True))
			elif isinstance(element, str):
				if not islink(element):
					if isdir(element):
						filePaths = []
						for root, directoryNames, fileNames in walk(element):
							for fileName in fileNames:
								absoluteFilePath = abspath(join(root, fileName))
								if (
									not islink(absoluteFilePath) and isfile(absoluteFilePath)
									and self.__getFileExtension(fileName) in self.__extensions and absoluteFilePath not in inputFilePaths
								):
									filePaths.append(absoluteFilePath)
						filePaths.sort()
						inputFilePaths.extend(filePaths)
						del filePaths
					elif isfile(element):
						fileName = basename(element)
						if self.__getFileExtension(fileName) in self.__extensions:
							absoluteFilePath = abspath(element)
							if absoluteFilePath not in inputFilePaths:
								inputFilePaths.append(absoluteFilePath)
		return tuple(inputFilePaths)
	def __format(self:object, _d:str = "", _n:str = "", _p:str = "", _x:str = "") -> str:
		d, n, p, x = _d if isinstance(_d, str) else "", _n if isinstance(_n, str) else "", _p if isinstance(_p, str) else "", _x if isinstance(_x, str) else ""
		buffer, index, length = [], 0, len(self.__formatString)
		while index < length:
			if '%' == self.__formatString[index]:
				index += 1
				if index < length:
					if '%' == self.__formatString[index]:
						buffer.append("%")
					elif 'd' == self.__formatString[index]:
						buffer.append(d)
					elif 'n' == self.__formatString[index]:
						buffer.append(n)
					elif 'p' == self.__formatString[index]:
						buffer.append(p)
					elif 'x' == self.__formatString[index]:
						buffer.append(x)
					else:
						buffer.append("%" + self.__formatString[index])
					index += 1
				else:
					buffer.append("%")
					break
			else:
				buffer.append(self.__formatString[index])
				index += 1
		return "".join(buffer)
	def updateUnits(self:object, *units:tuple) -> int:
		originalLength, stack = len(self.__analyzers), list(reversed(units))
		while stack:
			element = stack.pop()
			if isinstance(element, (tuple, list)):
				stack.extend(reversed(element))
			elif isinstance(element, set):
				stack.extend(sorted(element, reverse = True))
			elif isinstance(element, str):
				try:
					if not islink(element):
						if isdir(element):
							filePaths = []
							for root, directoryNames, fileNames in walk(element):
								for fileName in fileNames:
									absoluteFilePath = abspath(join(root, fileName))
									if (
										not islink(absoluteFilePath) and isfile(absoluteFilePath)
										and self.__getFileExtension(fileName) in self.__extensions and absoluteFilePath not in self.__units
									):
										filePaths.append(absoluteFilePath)
							filePaths.sort()
							self.__units.extend(filePaths)
							del filePaths
						elif isfile(element):
							fileName = basename(element)
							if self.__getFileExtension(fileName) in self.__extensions:
								absoluteFilePath = abspath(element)
								if absoluteFilePath not in self.__units:
									self.__units.append(absoluteFilePath)
				except BaseException as e:
					print("Analyzers: Some or all of {0} were not added to the units due to {1}. ".format(repr(element), repr(e)))
			elif isinstance(element, dict) and "i" in element and isinstance(element["i"], (tuple, list, str)) and "o" in element and isinstance(element["o"], str):
				try:
					inputFilePaths = self.__getUnitInputFilePaths(element["i"])
					if inputFilePaths and next((unit for unit in self.__units if isinstance(unit, dict) and "i" in unit and inputFilePaths == unit["i"]), None) is None:
						self.__units.append({"i":inputFilePaths, "o":element["o"]})
				except BaseException as e:
					print("Analyzers: Failed to add the unit {0} to the units due to {1}. ".format(repr(element), repr(e)))
		index, length = originalLength, len(self.__units)
		while index < length:
			if isinstance(self.__units[index], str):
				dp, nx = split(self.__units[index])
				d, p = splitdrive(dp)
				n, x = splitext(nx)
				self.__analyzers.append(Analyzer(self.__units[index], self.__format(_d = d, _n = n, _p = p, _x = x), caseSensitive = self.__caseSensitive))
				index += 1
			elif (
				isinstance(self.__units[index], dict) and "i" in self.__units[index] and isinstance(self.__units[index]["i"], tuple)
				and "o" in self.__units[index] and isinstance(self.__units[index]["o"], str)
			):
				self.__analyzers.append(Analyzer(self.__units[index]["i"], self.__units[index]["o"], caseSensitive = self.__caseSensitive))
				index += 1
			else:
				del self.__units[index]
		currentLength = len(self.__analyzers)
		return currentLength - originalLength
	def analyze(self:object) -> int:
		successCount = 0
		for unit, analyzer in zip(self.__units, self.__analyzers):
			result = analyzer.analyze()
			if result is True:
				successCount += 1
			print("Analyzers: {0} -> {1}".format(repr(unit), repr(result) if isinstance(result, BaseException) else result))
		return successCount
	def __len__(self:object) -> int:
		return len(self.__analyzers)


def main() -> int:
	flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, units = Parser.parse(argv)
	Parser.disableConsoleEchoes()
	if flag > EXIT_SUCCESS and flag > EOF:
		analyzers = Analyzers(units, extensions = {".csv", ".xlsx"}, formatString = outputPathWithoutAnExtension)
		totalCount = len(analyzers)
		if totalCount >= 1:
			successCount = analyzers.analyze()
			print()
			errorLevel = EXIT_SUCCESS if successCount == totalCount else EXIT_FAILURE
		else:
			errorLevel = EOF
			print("Nothing analyzed, please check the input paths and the runtime environments. ")
	elif EXIT_SUCCESS == flag:
		errorLevel = flag
	else:
		errorLevel = EOF
	if 0 == waitingTime:
		print("The execution has finished ({0}). ".format(errorLevel))
		print()
	elif isinstance(waitingTime, (float, int)) and 0 < waitingTime < float("inf"):
		integerTime, timeString = int(waitingTime), str(waitingTime)
		decimalTime = waitingTime - integerTime
		if "e" in timeString:
			timeString = str(integerTime) + ("{{0:.{0}f}}".format(decimalPlace).format(decimalTime).strip("0").rstrip(".") if decimalTime >= 10 ** (-decimalPlace) else "")
		timeStringLength = len(timeString)
		print("Please wait {0} second(s) for automatic exit, or exit manually, for example by pressing ``Ctrl + C`` ({1}). ".format(timeString, errorLevel))
		try:
			print("\rThe countdown is {0} second(s). ".format(timeString, errorLevel), end = "")
			sleep(decimalTime)
			while integerTime >= 1:
				print("\rThe countdown is {{0:>{0}}} second(s). ".format(timeStringLength).format(integerTime, errorLevel), end = "")
				sleep(1)
				integerTime -= 1
		except:
			pass
		print("\rThe countdown is {{0:>{0}}} second(s). ".format(timeStringLength).format(0, errorLevel))
		print("The execution has finished ({0}). ".format(errorLevel))
		print()
	else:
		print("Please press the Enter key to exit ({0}). ".format(errorLevel))
		try:
			getpass("")
		except:
			print()
	Parser.restoreConsoleEchoes()
	return errorLevel



if "__main__" == __name__:
	exit(main())