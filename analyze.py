from os import chdir, makedirs, name, walk
from os.path import abspath, basename, dirname, isdir, isfile, islink, join, split, splitdrive, splitext
from sys import argv, exit
from getpass import getpass
from io import BytesIO
from math import isfinite
from re import findall, fullmatch
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
		print("This is the official cryptographic scheme drawer. ")
		print()
		print("Options (case-insensitive): ")
		print("\t{0}\t\tIndicate that all the subsequent arguments are file paths. ".format(Parser.__formatOption(Parser.__OptionDelimiter)))
		print("\t{0}\t\tPrint this help document. ".format(Parser.__formatOption(Parser.__OptionHelp)))
		print((
			"\t{0} <output>\t\tSpecify the output path without an extension, which can be a format string, "
			+ "where %%, %d, %n, %p, %x stand for the %, Drive letter (if applicable), main file Name, directory Path, and eXtension, respectively. The default value is {1}. "
		).format(Parser.__formatOption(Parser.__OptionOutput), Parser.__DefaultOutput))
		print("\t{0} [s|ms|microsecond|ns|ps|0|3|6|9|12|...]\t\tSpecify the decimal place, which should be a non-negative integer. The default value is {1}. ".format(
			Parser.__formatOption(Parser.__OptionPlace), Parser.__DefaultPlace
		))
		print(
			"\t{0} [0|0.1|1|10|...|inf]\t\tSpecify the waiting time before exiting, which should be non-negative. ".format(Parser.__formatOption(Parser.__OptionTime))
			+ "Passing inf requires users to manually press the Enter key before exiting. The default value is {0}. ".format(Parser.__DefaultTime)
		)
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
		flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, paths = max(EXIT_SUCCESS, EOF) + 1, Parser.__DefaultOutput, Parser.__DefaultPlace, Parser.__DefaultTime, []
		index, argumentCount, nonOptionMode, buffers = 1, len(arguments), False, []
		while index < argumentCount:
			argument = arguments[index].lower()
			if nonOptionMode:
				paths.append(arguments[index])
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
			else:
				paths.append(argument)
			index += 1
		if EOF == flag:
			for buffer in buffers:
				print(buffer)
		return (flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, paths)
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
	def load(inputFilePath:str, caseSensitive:bool = False) -> dict|BaseException|None: # {"x":[1, 2, 3], "y":[1, 4, 9]}
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
						keywordArguments = {key:value for key, value in curve.items() if key in ("color", "marker", "label")}
						try:
							Drawer.__plt.plot(curve["x"], curve["y"], **keywordArguments)
						except Exception:
							Drawer.__plt.plot(curve["x"], curve["y"])
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
	def drawMappings(mappings:dict, independentVariables:tuple|list, dependentVariables:tuple|list, groupVariables:tuple|list) -> dict|BaseException:
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
			groupVariableNames = []
			if isinstance(groupVariables, (tuple, list)):
				for groupVariable in groupVariables:
					variableName = __getVariableName(groupVariable)
					if isinstance(variableName, str):
						groupVariableNames.append(variableName)
			else:
				variableName = __getVariableName(groupVariables)
				if isinstance(variableName, str):
					groupVariableNames.append(variableName)
			del __getVariableName
			if independentVariableNames and dependentVariableNames and groupVariableNames:
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
				for groupVariableName in groupVariableNames:
					if groupVariableName in seenVariableNames:
						return ValueError("The group variable {0} is repeated. ".format(repr(groupVariableName)))
					else:
						seenVariableNames.add(groupVariableName)
				del seenVariableNames
				if Drawer.__plt is None:
					configurationStatus = Drawer.configure()
					if configurationStatus is not True:
						return configurationStatus
				valueLength = len(next(iter(mappings.values())))
				byteMappings = {}
				for groupVariableName in groupVariableNames:
					groupVariableIndex = variables.index(groupVariableName) # for naming purposes
					groupVariableValues = []
					for valueIndex in range(valueLength): # start to make the color and the marker for the same group variable value the same across different figures
						groupVariableValues.append(mappings[groupVariableName][valueIndex])
					colors = {groupVariableValue:Drawer.__Colors[enumerationIndex % Drawer.__ColorLength] for (
						enumerationIndex, groupVariableValue
					) in enumerate(groupVariableValues)}
					markers = {groupVariableValue:Drawer.__Markers[enumerationIndex % Drawer.__MarkerLength] for (
						enumerationIndex, groupVariableValue
					) in enumerate(groupVariableValues)} # finish
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
									groupVariableValue = mappings[groupVariableName][valueIndex]
									curveMappings.setdefault(groupVariableValue, {})
									curveMappings[groupVariableValue].setdefault(
										mappings[independentVariableName][valueIndex], []
									).append(mappings[dependentVariableName][valueIndex]) # to avoid multiple ``y`` values
								curves = []
								for outerKey, outerValue in curveMappings.items(): # groupVariableValue -> {x -> y(s)}
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
	def __init__(self:object, inputFilePath:str, outputFilePath:str, caseSensitive:bool = False) -> object:
		self.__inputFilePath = inputFilePath
		self.__outputFilePath = outputFilePath
		self.__caseSensitive = caseSensitive is True
	@staticmethod
	def __escapeTEX(value:object, breakable:bool = False) -> str:
		escapedValue = "\\textbackslash{}".join(
			string.replace("#", "\\#").replace("$", "\\$").replace("%", "\\%").replace("&", "\\&")
			.replace("_", "\\_").replace("{", "\\{").replace("}", "\\}")
			.replace("<", "\\textless{}").replace(">", "\\textgreater{}")
			.replace("^", "\\textasciicircum{}").replace("~", "\\textasciitilde{}")
			for string in "".join(character for character in str(value) if ' ' <= character <= '~').split("\\")
		)
		if breakable is True:
			escapedValue = escapedValue.replace("\\_", "\\_\\allowbreak{}").replace(".", ".\\allowbreak{}").replace("/", "/\\allowbreak{}")
		return escapedValue
	@staticmethod
	def __checkValues(values:tuple|list) -> bool:
		return isinstance(values, (tuple, list)) and values and all(isinstance(value, (int, float, str)) for value in values)
	@staticmethod
	def __formatTEXList(values:tuple|list) -> str:
		valueStrings = tuple(str(value) for value in values)
		if len(valueStrings) >= 3:
			return ", ".join(valueStrings[:-1]) + ", and " + valueStrings[-1]
		elif 2 == len(valueStrings):
			return " and ".join(valueStrings)
		elif 1 == len(valueStrings):
			return valueStrings[0]
		else:
			return ""
	@staticmethod
	def __getOptimalValueIndexes(
		mappings:dict, groupVariableIndex:int, runCountVariableIndex:int, dependentVariableIndexes:tuple|list
	) -> set:
		variables = tuple(mappings.keys())
		comparisonVariableNames = tuple(
			variableName for variableIndex, variableName in enumerate(variables[:runCountVariableIndex]) if variableIndex != groupVariableIndex
		)
		valueIndexGroups = {}
		for valueIndex in range(len(next(iter(mappings.values())))):
			valueIndexGroups.setdefault(
				tuple(mappings[variableName][valueIndex] for variableName in comparisonVariableNames), []
			).append(valueIndex)
		optimalValueIndexes = set()
		for valueIndexGroup in valueIndexGroups.values():
			for dependentVariableIndex in dependentVariableIndexes:
				dependentVariableName = variables[dependentVariableIndex]
				numericValues = tuple(
					(valueIndex, mappings[dependentVariableName][valueIndex]) for valueIndex in valueIndexGroup if (
						isinstance(mappings[dependentVariableName][valueIndex], (int, float))
						and not isinstance(mappings[dependentVariableName][valueIndex], bool)
						and isfinite(float(mappings[dependentVariableName][valueIndex]))
					)
				)
				if numericValues:
					optimalValue = min(value for _, value in numericValues)
					optimalValueIndexes.update(
						(valueIndex, dependentVariableIndex) for valueIndex, value in numericValues if value == optimalValue
					)
		return optimalValueIndexes
	@staticmethod
	def __makeFigureCaption(fileName:str, variables:tuple|list) -> str:
		match = fullmatch(r"x([0-9]+)y([0-9]+)((?:c[0-9]+)*)g([0-9]+)\.pdf", fileName)
		if match is None:
			return "The generated mapping figure."
		independentVariableIndex, dependentVariableIndex, controlledVariableString, groupIndex = (
			int(match.group(1)), int(match.group(2)), match.group(3), int(match.group(4))
		)
		controlledVariableIndexes = tuple(int(value) for value in findall(r"c([0-9]+)", controlledVariableString))
		if not (
			0 <= independentVariableIndex < len(variables) and 0 <= dependentVariableIndex < len(variables)
			and all(0 <= controlledVariableIndex < len(variables) for controlledVariableIndex in controlledVariableIndexes)
		):
			return "The generated mapping figure."
		caption = "The {0} group of the mapping from {1} to {2}".format(
			groupIndex, Analyzer.__escapeTEX(variables[independentVariableIndex]), Analyzer.__escapeTEX(variables[dependentVariableIndex])
		)
		if controlledVariableIndexes:
			caption += " with {0} fixed".format(Analyzer.__formatTEXList(tuple(
				Analyzer.__escapeTEX(variables[controlledVariableIndex]) for controlledVariableIndex in controlledVariableIndexes
			)))
		return caption + "."
	@staticmethod
	def __makeMainTEX(
		mappings:dict, groupVariableIndex:int, runCountVariableIndex:int, dependentVariableIndexes:tuple|list, fileNames:tuple|list
	) -> str:
		variables = tuple(mappings.keys())
		optimalValueIndexes = Analyzer.__getOptimalValueIndexes(
			mappings, groupVariableIndex, runCountVariableIndex, dependentVariableIndexes
		)
		lines = [
			"\\documentclass[a4paper]{article}",
			"\\setlength{\\parindent}{0pt}",
			"\\usepackage[T1]{fontenc}",
			"\\usepackage{array}",
			"\\usepackage{graphicx}",
			"\\usepackage{longtable}",
			"\\usepackage{textcomp}",
			"",
			"\\begin{document}",
			"",
			"\\section*{Mappings}",
			"Bold metric values are optimal among records whose non-group query values are identical; ties are all bold.",
			"",
			"\\begin{longtable}{@{}r>{\\raggedright\\arraybackslash}p{0.86\\textwidth}@{}}",
			"\\hline",
			"\\textbf{Record} & \\textbf{Mapping} \\\\",
			"\\hline",
			"\\endfirsthead",
			"\\hline",
			"\\textbf{Record} & \\textbf{Mapping} \\\\",
			"\\hline",
			"\\endhead",
			"\\hline",
			"\\endfoot",
		]
		for valueIndex in range(len(next(iter(mappings.values())))):
			mappingStrings = []
			for variableIndex, variableName in enumerate(variables):
				value = mappings[variableName][valueIndex]
				valueString = Analyzer.__escapeTEX(value, breakable = isinstance(value, str))
				if (valueIndex, variableIndex) in optimalValueIndexes:
					valueString = "\\textbf{{{0}}}".format(valueString)
				mappingStrings.append("\\texttt{{{0}}} = {1}".format(Analyzer.__escapeTEX(variableName), valueString))
			lines.append("{0} & {1} \\\\".format(valueIndex + 1, ";\\allowbreak ".join(mappingStrings)))
		lines.extend((
			"\\end{longtable}",
			"",
			"\\newpage",
			"\\section*{Figures}",
		))
		for fileName in fileNames:
			lines.extend((
				"\\begin{figure}[htbp]",
				"\\centering",
				"\\includegraphics[width=\\linewidth]{{{0}}}".format(Analyzer.__escapeTEX(fileName)),
				"\\caption{{{0}}}".format(Analyzer.__makeFigureCaption(fileName, variables)),
				"\\label{{fig:{0}}}".format(Analyzer.__escapeTEX(splitext(fileName)[0])),
				"\\end{figure}",
				"",
			))
		lines.append("\\end{document}")
		return "\n".join(lines)
	def analyze(self:object) -> bool|dict|BaseException:
		mappings = Loader.load(self.__inputFilePath, caseSensitive = self.__caseSensitive)
		if isinstance(mappings, BaseException):
			return IOError("Failed to load mappings from {0} due to {1}. ".format(repr(self.__inputFilePath), repr(mappings)))
		elif isinstance(mappings, dict) and all(isinstance(key, str) and Analyzer.__checkValues(value) for key, value in mappings.items()) and len(set(len(value) for value in mappings.values())) == 1:
			variables = tuple(mappings.keys())
			if "solution" in variables:
				groupVariableIndex = variables.index("solution")
			elif "scheme" in variables:
				groupVariableIndex = variables.index("scheme")
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
				independentVariableIndexes = tuple(variableIndex for variableIndex in range(secparamVariableIndex, runCountVariableIndex) if variableIndex != groupVariableIndex)
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
					byteMappings = Drawer.drawMappings(mappings, independentVariableIndexes, dependentVariableIndexes, groupVariableIndex)
					if isinstance(byteMappings, dict):
						__getFileExtension = (lambda x:splitext(x)[1]) if self.__caseSensitive else (lambda x:splitext(x)[1].lower())
						compressionMappings = {}
						pdfMappings = {}
						for key, value in byteMappings.items():
							if isinstance(key, str) and isinstance(value, bytes):
								fileName = key if ".pdf" == __getFileExtension(key) else key + ".pdf"
								pdfMappings[fileName] = value
							else:
								compressionMappings[key] = value
						with ZipFile(self.__outputFilePath if ".zip" == __getFileExtension(self.__outputFilePath) else self.__outputFilePath + ".zip", "w") as zf:
							for fileName, value in pdfMappings.items():
								zf.writestr(fileName, value)
							zf.writestr("main.tex", Analyzer.__makeMainTEX(
								mappings, groupVariableIndex, runCountVariableIndex, dependentVariableIndexes, tuple(pdfMappings.keys())
							))
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
	def __init__(self:object, *paths:tuple, caseSensitive:bool = False, extensions:tuple|list|set|str = __DefaultExtensions, formatString:str = __DefaultFormatString) -> object:
		self.__filePaths = []
		self.__analyzers = []
		self.__caseSensitive = caseSensitive is True
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
		self.updateFilePaths(*paths if paths else ".")
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
	def updateFilePaths(self:object, *paths:tuple) -> int:
		originalLength, stack = len(self.__analyzers), list(reversed(paths))
		__getFileExtension = (lambda x:splitext(x)[1]) if self.__caseSensitive else (lambda x:splitext(x)[1].lower())
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
									and __getFileExtension(fileName) in self.__extensions and absoluteFilePath not in self.__filePaths
								):
									filePaths.append(absoluteFilePath)
						filePaths.sort()
						self.__filePaths.extend(filePaths)
						del filePaths
					elif isfile(element):
						fileName = basename(element)
						if __getFileExtension(fileName) in self.__extensions:
							absoluteFilePath = abspath(element)
							if absoluteFilePath not in self.__filePaths:
								self.__filePaths.append(absoluteFilePath)
		del __getFileExtension
		for filePath in self.__filePaths[originalLength:]:
			dp, nx = split(filePath)
			d, p = splitdrive(dp)
			n, x = splitext(nx)
			self.__analyzers.append(Analyzer(filePath, self.__format(_d = d, _n = n, _p = p, _x = x), caseSensitive = self.__caseSensitive))
		currentLength = len(self.__analyzers)
		return currentLength - originalLength
	def analyze(self:object) -> int:
		successCount = 0
		for filePath, analyzer in zip(self.__filePaths, self.__analyzers):
			result = analyzer.analyze()
			if result is True:
				successCount += 1
			print("{0} -> {1}".format(repr(filePath), repr(result) if isinstance(result, BaseException) else result))
		return successCount
	def __len__(self:object) -> int:
		return len(self.__analyzers)


def main() -> int:
	flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, paths = Parser.parse(argv)
	Parser.disableConsoleEchoes()
	if flag > EXIT_SUCCESS and flag > EOF:
		analyzers = Analyzers(argv[1:], extensions = {".csv", ".xlsx"}, formatString = outputPathWithoutAnExtension)
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