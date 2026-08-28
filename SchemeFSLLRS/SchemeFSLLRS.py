from os import chdir, makedirs, name, sep
from os.path import abspath, basename, dirname, exists, isfile, isdir, join, split, splitext
from sys import argv, exit
from codecs import lookup
from getpass import getpass
from hashlib import sha3_256
try:
	from numpy import array, dot, eye, ndarray, sum as np_sum, zeros
	from numpy.random import randint
except:
	array, dot, eye, ndarray, np_sum, zeros, randint = (None, ) * 7
from time import perf_counter, sleep
try:
	chdir(abspath(dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)


class Parser:
	__SchemeName = "SchemeFSLLRS" # splitext(basename(__file__))[0]
	__OptionEncoding = ("e", "/e", "-e", "encoding", "/encoding", "--encoding")
	__DefaultEncoding = "utf-8"
	__OptionHelp = ("h", "/h", "-h", "help", "/help", "--help")
	__OptionOutput = ("o", "/o", "-o", "output", "/output", "--output")
	__DefaultOutputExtension = ".xlsx"
	__DefaultOutputFileName = __SchemeName + __DefaultOutputExtension
	__ProtectedExtensionNames = ("ASM", "BAT", "C", "CMD", "CPP", "CS", "GO", "H", "HPP", "IPYNB", "JAR", "JAVA", "JS", "KT", "LUA", "M", "O", "PHP", "PS1", "PY", "R", "RB", "RS", "S", "SH", "SQL")
	__OptionPlace = ("p", "/p", "-p", "place", "/place", "--place")
	__DefaultPlace = 9
	__PlaceTranslations = {"s":0, "second":0, "ms":3, "millisecond":3, "microsecond":6, "ns":9, "nanosecond":9, "ps":12, "picosecond":12, "fs":15, "femtosecond":15}
	__OptionQuiet = ("q", "/q", "-q", "quiet", "/quiet", "--quiet")
	__OptionRun = ("r", "/r", "-r", "run", "/run", "--run")
	__DefaultRun = 10
	__OptionTime = ("t", "/t", "-t", "time", "/time", "--time")
	__DefaultTime = float("inf")
	__OptionYes = ("y", "/y", "-y", "yes", "/yes", "--yes")
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
		print("This is the official simulation implementation of the FS-LLRS cryptographic scheme in the Python programming language based on the Python NumPy library. ")
		print()
		print("Options (case-insensitive): ")
		print("\t{0} [utf-8|utf-16|...]\t\tSpecify the encoding mode for CSV and TXT outputs. The default value is {1}. ".format(
			Parser.__formatOption(Parser.__OptionEncoding), Parser.__DefaultEncoding
		))
		print("\t{0}\t\tPrint this help document. ".format(Parser.__formatOption(Parser.__OptionHelp)))
		print("\t{0} [|.|./{1}.xlsx|./{1}.csv|...]\t\tSpecify the output file path, leaving it empty for console output. The default value is {2}. ".format(
			Parser.__formatOption(Parser.__OptionOutput), Parser.__SchemeName, repr(Parser.__DefaultOutputFileName)
		))
		print("\t{0} [s|ms|microsecond|ns|ps|0|3|6|9|12|...]\t\tSpecify the decimal place, which should be a non-negative integer. The default value is {1}. ".format(
			Parser.__formatOption(Parser.__OptionPlace), Parser.__DefaultPlace
		))
		print("\t{0}\t\tDisable the verbose console outputs. ".format(Parser.__formatOption(Parser.__OptionQuiet)))
		print("\t{0} [1|2|5|10|20|50|100|...]\t\tSpecify the run count, which must be a positive integer. The default value is {1}. ".format(
			Parser.__formatOption(Parser.__OptionRun), Parser.__DefaultRun
		))
		print(
			"\t{0} [0|0.1|1|10|...|inf]\t\tSpecify the waiting time before exiting, which should be non-negative. ".format(Parser.__formatOption(Parser.__OptionTime))
			+ "Passing inf requires users to manually press the Enter key before exiting. The default value is {0}. ".format(Parser.__DefaultTime)
		)
		print("\t{0}\t\tIndicate to confirm the overwriting of the existing output file. ".format(Parser.__formatOption(Parser.__OptionYes)))
		print()
	@staticmethod
	def __handlePath(filePath:str) -> str:
		if isinstance(filePath, str):
			if isdir(filePath) or filePath.endswith((sep, "/")):
				print("Parser: The output file path passed looks like a directory, which would be connected with the default file name {0}. ".format(repr(Parser.__DefaultOutputFileName)))
				return Parser.__handlePath(join(filePath, Parser.__DefaultOutputFileName))
			elif splitext(basename(filePath))[1][1:].upper() in Parser.__ProtectedExtensionNames:
				print((
					"Parser: The extension name of the output file path passed is one of the protected extension names, "
					+ "which would be reset to the default extension {0}. "
				).format(repr(Parser.__DefaultOutputExtension)))
				return Parser.__handlePath(splitext(filePath)[0] + Parser.__DefaultOutputExtension)
			else:
				return filePath
		else:
			return Parser.__DefaultOutputFileName
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
		flag, encoding, outputFilePath, decimalPlace, isVerbose, runCount, waitingTime, overwritingConfirmed = (
			max(EXIT_SUCCESS, EOF) + 1, Parser.__DefaultEncoding, Parser.__DefaultOutputFileName, Parser.__DefaultPlace, True, Parser.__DefaultRun, Parser.__DefaultTime, False
		)
		index, argumentCount, buffers = 1, len(arguments), []
		while index < argumentCount:
			argument = arguments[index].lower()
			if argument in Parser.__OptionEncoding:
				index += 1
				if index < argumentCount:
					try:
						lookup(arguments[index])
						encoding = arguments[index]
					except:
						flag = EOF
						buffers.append("Parser: The value [0] = {1} for the encoding option is invalid. ".format(index, repr(arguments[index])))
				else:
					flag = EOF
					buffers.append("Parser: The value for the encoding option is missing at [{0}]. ".format(index))
			elif argument in Parser.__OptionHelp:
				Parser.__printHelp()
				flag = EXIT_SUCCESS
				break
			elif argument in Parser.__OptionOutput:
				index += 1
				if index < argumentCount:
					outputFilePath = Parser.__handlePath(arguments[index])
				else:
					flag = EOF
					buffers.append("Parser: The value for the output file path option is missing at [{0}]. ".format(index))
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
			elif argument in Parser.__OptionQuiet:
				isVerbose = False
			elif argument in Parser.__OptionRun:
				index += 1
				if index < argumentCount:
					r = Parser.__parseRealNumber(arguments[index])
					if r is None:
						flag = EOF
						buffers.append("Parser: The type of the value [{0}] = {1} for the run count option is invalid. ".format(index, repr(arguments[index])))
					elif isinstance(r, int) and r >= 1:
						runCount = r
					else:
						flag = EOF
						buffers.append("Parser: The value [{0}] = {1} for the run count option should be a positive integer. ".format(index, r))
					del r
				else:
					flag = EOF
					buffers.append("Parser: The value for the run count option is missing at [{0}]. ".format(index))
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
			elif argument in Parser.__OptionYes:
				overwritingConfirmed = True
			else:
				flag = EOF
				buffers.append("Parser: The option [{0}] = {1} is unknown. ".format(index, repr(arguments[index])))
			index += 1
		if EOF == flag:
			for buffer in buffers:
				print(buffer)
		return (flag, encoding, outputFilePath, decimalPlace, isVerbose, runCount, waitingTime, overwritingConfirmed)
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
	def checkOverwriting(outputFP:str, overwriting:bool) -> tuple:
		if isinstance(outputFP, str) and isinstance(overwriting, bool):
			outputFilePath, overwritingConfirmed, flag = outputFP, overwriting, False
			while outputFilePath and exists(outputFilePath):
				if isfile(outputFilePath):
					if not overwritingConfirmed:
						flag = True
						try:
							overwritingConfirmed = input(
								"The file {0} exists. Overwrite the file or not [yN]? ".format(repr(outputFilePath))
							).upper() in ("Y", "YES", "1", "T", "TRUE")
						except:
							print()
				else:
					flag = True
					print("Parser: The path {0} exists not to be a regular file. ".format(repr(outputFilePath)))
				if overwritingConfirmed:
					break
				else:
					flag = True
					try:
						outputFilePath = Parser.__handlePath(input("Please specify a new output file path or leave it empty for console output: "))
					except:
						print()
			if flag:
				print()
			return (outputFilePath, overwritingConfirmed)
		else:
			return (outputFP, overwriting)
	@staticmethod
	def getDefaultOutputFilePath() -> str:
		return Parser.__DefaultOutputFileName
	@staticmethod
	def getDefaultPlace() -> int:
		return Parser.__DefaultPlace
	@staticmethod
	def getDefaultEncoding() -> str:
		return Parser.__DefaultEncoding
	@staticmethod
	def getSchemeName() -> str:
		return Parser.__SchemeName
	@staticmethod
	def getProtectedExtensionNames() -> tuple:
		return Parser.__ProtectedExtensionNames
	@staticmethod
	def restoreConsoleEchoes() -> bool:
		if "posix" == name:
			try:
				Parser.__tcsetattr(0, 0, Parser.__OriginalConsoleAttributes)
				Parser.__OriginalConsoleAttributes = None
			except:
				return False
		return True

class Saver:
	__Writer = None # CSV/TSV
	__escapeHTML = None # HTM/HTML
	__dumpsJSON = None # JSON/YAML/YML
	__escapeTEX = None # TEX
	__columnsTEX = None # TEX
	__WorkbookXLS = None #XLS
	__styleXLSColumns = None # XLS
	__styleXLSValues = None # XLS
	__WorkbookXLSX = None # XLSX
	__alignmentXLSX = None # XLSX
	__fontXLSXColumns = None # XLSX
	__fontXLSXValues = None # XLSX
	__escapeXLSX = None # XLSX
	__escapeXML = None # XML
	def __init__(
		self:object, outputFilePath:str = Parser.getDefaultOutputFilePath(), columns:tuple|list = tuple(), decimalPlace:int = Parser.getDefaultPlace(), encoding:str = Parser.getDefaultEncoding()
	) -> object:
		self.__outputFilePath = outputFilePath if isinstance(outputFilePath, str) else Parser.getDefaultOutputFilePath()
		self.__columns = tuple(column for column in columns if isinstance(column, str)) if isinstance(columns, (tuple, list)) else tuple()
		self.__decimalPlace = decimalPlace if isinstance(decimalPlace, int) and decimalPlace >= 0 else Parser.getDefaultPlace()
		self.__encoding = encoding if isinstance(encoding, str) else Parser.getDefaultEncoding()
		self.__directoryPath = dirname(self.__outputFilePath)
		self.__extensionName = splitext(basename(self.__outputFilePath))[1][1:].upper()
	def __handleDirectory(self:object) -> bool:
		if not self.__directoryPath:
			return True
		elif exists(self.__directoryPath):
			return isdir(self.__directoryPath)
		else:
			try:
				makedirs(self.__directoryPath)
				return True
			except:
				return False
	def save(self:object, results:tuple|list) -> bool:
		if isinstance(results, (tuple, list)) and all(isinstance(result, (tuple, list)) and all(r is None or isinstance(r, (bool, float, int, str)) for r in result) for result in results):
			if self.__outputFilePath:
				if self.__handleDirectory():
					flag = True
					while True: # try our best to avoid ``KeyboardInterrupt`` when writing the output file
						if flag and self.__extensionName != "TXT":
							try:
								if "CSV" == self.__extensionName:
									if Saver.__Writer is None:
										Saver.__Writer = __import__("csv").writer
									with open(self.__outputFilePath, "w", newline = "", encoding = self.__encoding) as f:
										writer = Saver.__Writer(f)
										writer.writerow(self.__columns)
										for result in results:
											writer.writerow("{{0:.{0}f}}".format(self.__decimalPlace).format(r) if isinstance(r, float) else r for r in result)
								elif self.__extensionName in ("HTM", "HTML"):
									if Saver.__escapeHTML is None:
										Saver.__escapeHTML = (
											lambda x:str(x).replace("&", "&amp;").replace('"', "&quot;").replace("'", "&#39;")
											.replace("<", "&lt;").replace(">", "&gt;").replace("\r\n", "<br />").replace("\n", "<br />").replace("\r", "<br />")
										)
									with open(self.__outputFilePath, "w", encoding = self.__encoding) as f:
										f.write("<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset=\"{0}\" />\n".format(self.__encoding.upper()))
										f.write("\t\t<title>{0}</title>\n\t\t<style>\n".format(Parser.getSchemeName()))
										f.write("\t\t\ttable {\n\t\t\t\tfont-family: \'Times New Roman\', serif;\n\t\t\t\twidth: 80%;\n")
										f.write("\t\t\t\tmargin: 20px auto;\n\t\t\t\tborder-top: 2px solid black;\n")
										f.write("\t\t\t\tborder-bottom: 2px solid black;\n\t\t\t\tborder-collapse: collapse;\n\t\t\t}\n")
										f.write("\t\t\tth, td {\n\t\t\t\tpadding: 8px 12px;\n\t\t\t\tborder: none;\n\t\t\t\ttext-align: center;\n\t\t\t}\n")
										f.write("\t\t\tthead tr {\n\t\t\t\tborder-bottom: 1.5px solid #000;\n\t\t\t}\n")
										f.write("\t\t\tth {\n\t\t\t\tfont-weight: bold;\n\t\t\t}\n")
										f.write("\t\t\tcaption {\n\t\t\t\tfont-size: 1.5em;\n\t\t\t\tfont-weight: bold;\n")
										f.write("\t\t\t\tmargin: 10px;\n\t\t\t\tcaption-side: top;\n\t\t\t}\n")
										f.write("\t\t</style>\n\t</head>\n\t<body>\n\t\t<table>\n")
										f.write("\t\t\t<caption>{0}</caption>\n\t\t\t<thead>\n\t\t\t\t<tr>\n".format(Parser.getSchemeName()))
										for column in self.__columns:
											f.write("\t\t\t\t\t<th>{0}</th>\n".format(Saver.__escapeHTML(column)))
										f.write("\t\t\t\t</tr>\n\t\t\t</thead>\n\t\t\t<tbody>\n")
										for result in results:
											f.write("\t\t\t\t<tr>\n")
											for r in result:
												f.write("\t\t\t\t\t<td>{0}</td>\n".format(
													"{{0:.{0}f}}".format(self.__decimalPlace).format(r) if isinstance(r, float) else Saver.__escapeHTML(r)
												))
											f.write("\t\t\t\t</tr>\n")
										f.write("\t\t\t</tbody>\n\t\t</table>\n\t</body>\n</html>")
								elif "JSON" == self.__extensionName:
									if Saver.__dumpsJSON is None:
										Saver.__dumpsJSON = __import__("json").dumps
									with open(self.__outputFilePath, "w", encoding = self.__encoding) as f:
										f.write(Saver.__dumpsJSON({"columns":self.__columns, "results":results}, indent = "\t", sort_keys = True, ensure_ascii = True))
								elif "TEX" == self.__extensionName:
									if Saver.__escapeTEX is None:
										Saver.__escapeTEX = lambda x:"\\textbackslash{}".join(
											string.replace("#", "\\#").replace("$", "\\$").replace("%", "\\%").replace("&", "\\&")
											.replace("_", "\\_").replace("{", "\\{").replace("}", "\\}")
											.replace("<", "\\textless{}").replace(">", "\\textgreater{}")
											.replace("^", "\\textasciicircum{}").replace("~", "\\textasciitilde{}")
											for string in "".join(character for character in str(x) if ' ' <= character <= '~').split("\\")
										)
									with open(self.__outputFilePath, "w", encoding = self.__encoding) as f:
										maxLength = max(
											len(Saver.__columnsTEX) if isinstance(Saver.__columnsTEX, (tuple, list)) else 0, 
											max(len(result) for result in results)
										)
										f.write("\\documentclass[a4paper]{article}\n\\setlength{\\parindent}{0pt}\n")
										f.write("\\usepackage{graphicx}\n\\usepackage{textcomp}\n\\usepackage{booktabs}\n\\usepackage{rotating}\n\n")
										f.write("\\begin{document}\n\n\\begin{sidewaystable}\n\t\\caption{The comparison results. }\n")
										f.write("\t\\label{tab:comparison}\n\t\\centering\n\t\\resizebox{\\textwidth}{!}{%\n\t\t\\begin{tabular}{")
										f.write("c" * maxLength + "}\n\t\t\t\\toprule\n\t\t\t\t")
										if self.__columns:
											f.write(" & ".join("\\textbf{{{0}}}".format(Saver.__escapeTEX(column)) for column in self.__columns))
											if len(self.__columns) < maxLength:
												f.write(" & \\textbf{~}" * (maxLength - len(self.__columns)))
										else:
											f.write(" & ".join(("\\textbf{~}", ) * maxLength))
										f.write(" \\\\\n\t\t\t\\midrule\n")
										for result in results:
											if result:
												f.write("\t\t\t\t")
												f.write(" & ".join(
													(
														"${0}$" if isinstance(r, int) else "${{0:.{0}f}}$".format(self.__decimalPlace)
													).format(r) if (
														isinstance(r, (float, int)) and not isinstance(r, bool)
													) else Saver.__escapeTEX(r) for r in result
												))
												if len(result) < maxLength:
													f.write(" & ~" * (maxLength - len(result)))
												f.write(" \\\\\n")
										f.write("\t\t\t\\bottomrule\n\t\t\\end{tabular}\n\t}\n")
										f.write("\\end{sidewaystable}\n\n\\end{document}")
								elif "TSV" == self.__extensionName:
									if Saver.__Writer is None:
										Saver.__Writer = __import__("csv").writer
									with open(self.__outputFilePath, "w", newline = "", encoding = self.__encoding) as f:
										writer = Saver.__Writer(f, delimiter = '\t')
										writer.writerow(self.__columns)
										for result in results:
											writer.writerow("{{0:.{0}f}}".format(self.__decimalPlace).format(r) if isinstance(r, float) else r for r in result)
								elif "XLS" == self.__extensionName:
									if Saver.__WorkbookXLS is None:
										Saver.__WorkbookXLS = __import__("xlwt").Workbook
									if Saver.__styleXLSColumns is None:
										Saver.__styleXLSColumns = __import__("xlwt").XFStyle()
										Saver.__styleXLSColumns.font = __import__("xlwt").Font()
										Saver.__styleXLSColumns.font.name = "Times New Roman"
										Saver.__styleXLSColumns.font.height = 240 # 12 * 20
										Saver.__styleXLSColumns.font.bold = True
										Saver.__styleXLSColumns.alignment = __import__("xlwt").Alignment()
										Saver.__styleXLSColumns.alignment.horz = __import__("xlwt").Alignment.HORZ_CENTER
										Saver.__styleXLSColumns.alignment.vert = __import__("xlwt").Alignment.VERT_CENTER
									if Saver.__styleXLSValues is None:
										Saver.__styleXLSValues = __import__("xlwt").XFStyle()
										Saver.__styleXLSValues.font = __import__("xlwt").Font()
										Saver.__styleXLSValues.font.name = "Times New Roman"
										Saver.__styleXLSValues.font.height = 240 # 12 * 20
										Saver.__styleXLSValues.alignment = __import__("xlwt").Alignment()
										Saver.__styleXLSValues.alignment.horz = __import__("xlwt").Alignment.HORZ_CENTER
										Saver.__styleXLSValues.alignment.vert = __import__("xlwt").Alignment.VERT_CENTER
									workbook = Saver.__WorkbookXLS(encoding = self.__encoding)
									worksheet = workbook.add_sheet(Parser.getSchemeName())
									for columnIndex, columnName in enumerate(self.__columns):
										worksheet.write(0, columnIndex, columnName, Saver.__styleXLSColumns)
									for i, result in enumerate(results, start = 1):
										for j, r in enumerate(result):
											worksheet.write(
												i, j, "{{0:.{0}f}}".format(self.__decimalPlace).format(r) if isinstance(r, float) else r, Saver.__styleXLSValues
											)
									workbook.save(self.__outputFilePath)
								elif "XLSX" == self.__extensionName:
									if Saver.__WorkbookXLSX is None:
										Saver.__WorkbookXLSX = __import__("openpyxl").Workbook
									if Saver.__alignmentXLSX is None:
										Saver.__alignmentXLSX = __import__("openpyxl").styles.Alignment(horizontal = "center", vertical = "center")
									if Saver.__fontXLSXColumns is None:
										Saver.__fontXLSXColumns = __import__("openpyxl").styles.Font(name = "Times New Roman", size = 12, bold = True)
									if Saver.__fontXLSXValues is None:
										Saver.__fontXLSXValues = __import__("openpyxl").styles.Font(name = "Times New Roman", size = 12)
									if Saver.__escapeXLSX is None:
										Saver.__escapeXLSX = lambda x:"".join(character for character in str(x) if character in ("\t", "\n", "\r") or character > ' ')
									workbook = Saver.__WorkbookXLSX()
									worksheet = workbook.active
									for columnIndex, columnName in enumerate(self.__columns, start = 1):
										cell = worksheet.cell(row = 1, column = columnIndex, value = Saver.__escapeXLSX(columnName))
										cell.alignment = Saver.__alignmentXLSX
										cell.font = Saver.__fontXLSXColumns
									for i, result in enumerate(results, start = 2):
										for j, r in enumerate(result, start = 1):
											if isinstance(r, float):
												cell = worksheet.cell(row = i, column = j, value = "{{0:.{0}f}}".format(self.__decimalPlace).format(r))
											elif isinstance(r, str):
												cell = worksheet.cell(row = i, column = j, value = Saver.__escapeXLSX(r))
											else:
												cell = worksheet.cell(row = i, column = j, value = r)
											cell.alignment = Saver.__alignmentXLSX
											cell.font = Saver.__fontXLSXValues
									worksheet.freeze_panes = "A2"
									workbook.save(self.__outputFilePath)
								elif "XML" == self.__extensionName:
									if Saver.__escapeXML is None:
										Saver.__escapeXML = (
											lambda x:"".join(character for character in str(x) if ' ' <= character <= '~')
											.replace("&", "&amp;").replace("\"", "&quot;").replace("\'", "&apos;").replace("<", "&lt;").replace(">", "&gt;")
										)
									with open(self.__outputFilePath, "w", encoding = self.__encoding) as f:
										f.write("<?xml version=\"1.0\" encoding=\"{0}\"?>\n<data>\n\t<columns>\n".format(self.__encoding.upper()))
										for column in self.__columns:
											f.write("\t\t<column>" + Saver.__escapeXML(column) + "</column>\n")
										f.write("\t</columns>\n\t<results>\n")
										for result in results:
											f.write("\t\t<result>\n")
											for rIndex, r in enumerate(result):
												if isinstance(r, float):
													f.write("\t\t\t<r>{{0:.{0}f}}</r>\n".format(self.__decimalPlace).format(r))
												else:
													f.write("\t\t\t<r>{0}</r>\n".format(Saver.__escapeXML(str(r))))
											f.write("\t\t</result>\n")
										f.write("\t</results>\n</data>")
								elif self.__extensionName in ("YAML", "YML"):
									if Saver.__dumpsJSON is None:
										Saver.__dumpsJSON = __import__("json").dumps
									with open(self.__outputFilePath, "w", encoding = self.__encoding) as f:
										if self.__columns:
											f.write("columns:\n")
											for column in self.__columns:
												f.write("  - {0}\n".format(Saver.__dumpsJSON(column, indent = "\t", sort_keys = True, ensure_ascii = True)))
										else:
											f.write("columns: []")
										f.write("\n")
										if results:
											f.write("results:\n")
											for result in results:
												if result:
													f.write("  - - {0}\n".format(
														Saver.__dumpsJSON(result[0], indent = "\t", sort_keys = True, ensure_ascii = True)
													))
													for r in result[1:]:
														f.write("    - {0}\n".format(
															Saver.__dumpsJSON(r, indent = "\t", sort_keys = True, ensure_ascii = True)
														))
												else:
													f.write("  - []")
										else:
											f.write("results: []")
								elif self.__extensionName in Parser.getProtectedExtensionNames():
									print("Saver: Failed to save the results to {0} since {1} is one of the protected extension names. ".format(
										repr(self.__outputFilePath), self.__extensionName
									))
									print("Saver: {0}".format({"columns":self.__columns, "results":results}))
									return False
								else:
									raise Exception("The {0} format is not supported. ".format(self.__extensionName))
								print("Saver: Successfully saved the results to {0} in the {1} format. ".format(repr(self.__outputFilePath), self.__extensionName))
								return True
							except KeyboardInterrupt:
								continue
							except BaseException as e:
								flag = False
								print("Saver: Failed to save the results to {0} in the {1} format due to the following exception(s). \n\t{2}".format(
									repr(self.__outputFilePath), self.__extensionName, repr(e)
								))
						else:
							try:
								with open(self.__outputFilePath, "w", encoding = self.__encoding) as f:
									f.write(str({"columns":self.__columns, "results":results}))
								print("Saver: Successfully saved the results to {0} in the TXT format. ".format(repr(self.__outputFilePath)))
								return True
							except KeyboardInterrupt:
								continue
							except BaseException as e:
								if flag:
									print("Saver: Failed to save the results to {0} due to the following exception(s). \n\t{1}".format(
										repr(self.__outputFilePath), repr(e)
									))
								else:
									print("\t{0}".format(e))
								print("Saver: {0}".format({"columns":self.__columns, "results":results}))
								return False
				else:
					print("Saver: Failed to initialize the directory for the output file path {0}. ".format(repr(self.__outputFilePath)))
					print("Saver: {0}".format({"columns":self.__columns, "results":results}))
					return False
			else:
				print("Saver: {0}".format({"columns":self.__columns, "results":results}))
				return True
		else:
			print("Saver: The results are invalid. ")
			return False

class SchemeFSLLRS:
	def __init__(self:object) -> object:
		self.__ringSize, self.__dimension, self.__modulus, self.__ringMatrix = (None, ) * 4
		self.__secretKeys, self.__publicKeys, self.__signer, self.__epoch = None, None, None, 0
		self.__message, self.__ringSignature, self.__linkedSignature = None, None, None
	def __hashScalar(self:object, *values:object) -> int:
		hashObject = sha3_256()
		for value in values:
			if isinstance(value, ndarray):
				encoded = value.astype("int64", copy = False).tobytes()
			elif isinstance(value, bytes):
				encoded = value
			else:
				encoded = str(value).encode()
			hashObject.update(len(encoded).to_bytes(8, byteorder = "big"))
			hashObject.update(encoded)
		return int.from_bytes(hashObject.digest(), byteorder = "big") % self.__modulus
	def LLRSSetup(self:object, ringSize:int, dimension:int, modulus:int) -> tuple:
		if not all(isinstance(value, int) and value > 1 for value in (ringSize, dimension, modulus)):
			raise ValueError("The ring size, dimension, and modulus must be integers greater than one. ")
		if ringSize & (ringSize - 1):
			raise ValueError("The ring size must be a power of two. ")
		self.__ringSize, self.__dimension, self.__modulus = ringSize, dimension, modulus
		diagonal = randint(1, modulus, size = (dimension, ))
		self.__ringMatrix = eye(dimension, dtype = "int") * diagonal
		self.__secretKeys, self.__publicKeys, self.__signer, self.__epoch = None, None, None, 0
		self.__message, self.__ringSignature, self.__linkedSignature = None, None, None
		return (self.__ringMatrix, ringSize, dimension, modulus)
	def KeyExtract(self:object) -> tuple:
		if self.__ringMatrix is None:
			raise RuntimeError("The scheme has not been set up. ")
		self.__secretKeys = randint(1, self.__modulus, size = (self.__ringSize, self.__dimension))
		self.__publicKeys = dot(self.__secretKeys, self.__ringMatrix.T) % self.__modulus
		return (self.__publicKeys, self.__secretKeys)
	def KeyUpdate(self:object) -> tuple:
		if self.__secretKeys is None:
			raise RuntimeError("The ring keys have not been extracted. ")
		self.__signer = int(randint(self.__ringSize))
		self.__epoch += 1
		updatedSecret = array([
			self.__hashScalar(self.__secretKeys[self.__signer], self.__epoch, index) or 1
			for index in range(self.__dimension)
		], dtype = "int")
		self.__secretKeys[self.__signer] = updatedSecret
		self.__publicKeys[self.__signer] = dot(self.__ringMatrix, updatedSecret) % self.__modulus
		return (self.__signer, self.__epoch, updatedSecret)
	def Sign(self:object, message:bytes|None = None) -> tuple:
		if self.__signer is None or self.__publicKeys is None or self.__secretKeys is None:
			raise RuntimeError("The signer key has not been updated. ")
		q, ringSize, dimension, signer = self.__modulus, self.__ringSize, self.__dimension, self.__signer
		self.__message = message if isinstance(message, bytes) else randint(0, 256, size = (32, ), dtype = "uint8").tobytes()
		challenges = randint(q, size = (ringSize, ))
		responses = randint(q, size = (ringSize, dimension))
		commitments = zeros((ringSize, dimension), dtype = "int")
		witness = randint(q, size = (dimension, ))
		for index in range(ringSize):
			if index == signer:
				commitments[index] = dot(self.__ringMatrix, witness) % q
			else:
				commitments[index] = (dot(self.__ringMatrix, responses[index]) - challenges[index] * self.__publicKeys[index]) % q
		challenge = self.__hashScalar(self.__message, self.__publicKeys, commitments)
		challenges[signer] = (challenge - np_sum(challenges) + challenges[signer]) % q
		responses[signer] = (witness + challenges[signer] * self.__secretKeys[signer]) % q
		tag = sha3_256(self.__secretKeys[signer].astype("int64", copy = False).tobytes()).digest()
		self.__ringSignature = (challenges, responses, tag)
		return self.__ringSignature
	def Verify(self:object, signature:tuple|None = None, message:bytes|None = None) -> bool:
		if self.__publicKeys is None or self.__ringMatrix is None:
			return False
		checkedSignature = signature if isinstance(signature, tuple) else self.__ringSignature
		checkedMessage = message if isinstance(message, bytes) else self.__message
		if not isinstance(checkedSignature, tuple) or len(checkedSignature) != 3 or not isinstance(checkedMessage, bytes):
			return False
		challenges, responses, tag = checkedSignature
		if not isinstance(challenges, ndarray) or challenges.shape != (self.__ringSize, ):
			return False
		if not isinstance(responses, ndarray) or responses.shape != (self.__ringSize, self.__dimension):
			return False
		if not isinstance(tag, bytes):
			return False
		commitments = zeros((self.__ringSize, self.__dimension), dtype = "int")
		for index in range(self.__ringSize):
			commitments[index] = (dot(self.__ringMatrix, responses[index]) - challenges[index] * self.__publicKeys[index]) % self.__modulus
		return bool(np_sum(challenges) % self.__modulus == self.__hashScalar(checkedMessage, self.__publicKeys, commitments))
	def Link(self:object) -> bool:
		if self.__ringSignature is None:
			return False
		firstSignature = self.__ringSignature
		secondSignature = self.Sign()
		self.__linkedSignature = secondSignature
		return bool(firstSignature[2] == secondSignature[2] and self.Verify(secondSignature, self.__message))
	def getLengthOf(self:object, obj:object) -> int|str:
		if isinstance(obj, ndarray):
			return int(obj.nbytes)
		elif isinstance(obj, bool):
			return 1
		elif isinstance(obj, int):
			return max(1, (abs(obj).bit_length() + 7) >> 3)
		elif isinstance(obj, bytes):
			return len(obj)
		elif isinstance(obj, str):
			return len(obj.encode())
		elif isinstance(obj, (tuple, list, set)):
			sizes = tuple(self.getLengthOf(value) for value in obj)
			return sum(sizes) if all(isinstance(size, int) and size >= 0 for size in sizes) else "N/A"
		elif isinstance(obj, dict):
			sizes = tuple(self.getLengthOf(value) for value in obj.values())
			return sum(sizes) if all(isinstance(size, int) and size >= 0 for size in sizes) else "N/A"
		else:
			return "N/A"


def conductScheme(parameter:tuple|list|dict, run:int|None = None, isVerbose:bool = False) -> list:
	NString, nString, qString, runString = ("N/A", ) * 4
	isSystemValid, isSchemeCorrect = (False, ) * 2
	timeSetup, timeKeyExtract, timeKeyUpdate, timeSign, timeVerify, timeLink = ("N/A", ) * 6
	sizePublicParameters, sizeSecretKeys, sizePublicKeys, sizeUpdatedKey, sizeSignature, sizeLinkedSignature = ("N/A", ) * 6
	if isinstance(parameter, (tuple, list)) and len(parameter) >= 3:
		N, n, q = parameter[:3]
	elif isinstance(parameter, dict):
		N, n, q = tuple(parameter.get(key) for key in ("N", "n", "q"))
	else:
		N, n, q = (None, ) * 3
	if all(isinstance(value, int) for value in (N, n, q)):
		NString, nString, qString = N, n, q
	if isinstance(run, int) and run >= 1:
		runString = run
	if isVerbose is not False:
		print("Parameters: (N = {0}, n = {1}, q = {2})".format(NString, nString, qString))
		print("run:", runString)
	try:
		if not all(isinstance(value, int) for value in (N, n, q)):
			raise ValueError("The parameters are invalid. ")
		scheme = SchemeFSLLRS()
		startTime = perf_counter()
		publicParameters = scheme.LLRSSetup(N, n, q)
		timeSetup = perf_counter() - startTime
		isSystemValid = True
		startTime = perf_counter()
		publicKeys, secretKeys = scheme.KeyExtract()
		timeKeyExtract = perf_counter() - startTime
		startTime = perf_counter()
		updatedKey = scheme.KeyUpdate()
		timeKeyUpdate = perf_counter() - startTime
		startTime = perf_counter()
		signature = scheme.Sign()
		timeSign = perf_counter() - startTime
		startTime = perf_counter()
		verified = scheme.Verify()
		timeVerify = perf_counter() - startTime
		startTime = perf_counter()
		linked = scheme.Link()
		timeLink = perf_counter() - startTime
		isSchemeCorrect = bool(verified and linked)
		sizePublicParameters = scheme.getLengthOf(publicParameters)
		sizeSecretKeys, sizePublicKeys = scheme.getLengthOf(secretKeys), scheme.getLengthOf(publicKeys)
		sizeUpdatedKey, sizeSignature = scheme.getLengthOf(updatedKey), scheme.getLengthOf(signature)
		sizeLinkedSignature = sizeSignature
		if isVerbose is not False:
			print("Is the system valid? Yes. ")
			print("Is the scheme correct? {0}. ".format("Yes" if isSchemeCorrect else "No"))
			print("Time:", (timeSetup, timeKeyExtract, timeKeyUpdate, timeSign, timeVerify, timeLink))
			print("Space:", (sizePublicParameters, sizeSecretKeys, sizePublicKeys, sizeUpdatedKey, sizeSignature, sizeLinkedSignature))
			print()
	except BaseException as e:
		if isVerbose is not False:
			print("Is the system valid? No. The execution failed due to {0}. ".format(repr(e)))
			print()
	return [
		Parser.getSchemeName(), NString, nString, qString, runString,
		isSystemValid, isSchemeCorrect,
		timeSetup, timeKeyExtract, timeKeyUpdate, timeSign, timeVerify, timeLink,
		sizePublicParameters, sizeSecretKeys, sizePublicKeys, sizeUpdatedKey, sizeSignature, sizeLinkedSignature
	]

def main() -> int:
	flag, encoding, outputFilePath, decimalPlace, isVerbose, runCount, waitingTime, overwritingConfirmed = Parser.parse(argv)
	if flag > EXIT_SUCCESS and flag > EOF:
		if any((array is None, dot is None, eye is None, ndarray is None, np_sum is None, zeros is None, randint is None)):
			Parser.disableConsoleEchoes()
			print("The runtime environment of the Python NumPy library is not correctly configured. ")
			print("Please install the libraries via the active Python package manager (e.g., pip). ")
			errorLevel = EOF
		else:
			outputFilePath, overwritingConfirmed = Parser.checkOverwriting(outputFilePath, overwritingConfirmed)
			Parser.disableConsoleEchoes()
			print("The execution has started. ")
			print()

			# Parameters #
			parameters = ((2, 4, 251), (4, 4, 251))
			queries = ("scheme", "N", "n", "q", "runCount")
			validators = ("isSystemValid", "isSchemeCorrect")
			metrics = (
				"Setup (s)", "KeyExtract (s)", "KeyUpdate (s)", "Sign (s)", "Verify (s)", "Link (s)",
				"publicParameters (B)", "secretKeys (B)", "publicKeys (B)", "updatedKey (B)", "signature (B)", "linkedSignature (B)"
			)

			# Scheme #
			columns, queryLength, results = queries + validators + metrics, len(queries), []
			queryValidatorLength, runCountIndex = queryLength + len(validators), queryLength - 1
			saver = Saver(outputFilePath, columns, decimalPlace = decimalPlace, encoding = encoding)
			try:
				for parameter in parameters:
					runs = [conductScheme(parameter, run = run, isVerbose = isVerbose) for run in range(1, runCount + 1)]
					averages = list(runs[0])
					for index in range(queryLength, queryValidatorLength):
						averages[index] = sum(int(result[index]) for result in runs)
					for index in range(queryValidatorLength, len(columns)):
						values = tuple(result[index] for result in runs)
						averages[index] = sum(values) / runCount if all(isinstance(value, (float, int)) and value > 0 for value in values) else "N/A"
						if isinstance(averages[index], float) and averages[index].is_integer():
							averages[index] = int(averages[index])
					averages[runCountIndex] = runCount
					results.append(averages)
					saver.save(results)
			except KeyboardInterrupt:
				print()
				print("The experiments were interrupted by users. Saved results are retained. ")
			except BaseException as e:
				print()
				print("The experiments were interrupted by {0}. Saved results are retained. ".format(repr(e)))
			errorLevel = EXIT_SUCCESS if results and all(
				all(result[index] == runCount for index in range(queryLength, queryValidatorLength))
				and all(isinstance(result[index], (float, int)) and result[index] > 0 for index in range(queryValidatorLength, len(columns)))
				for result in results
			) else EXIT_FAILURE
	elif EXIT_SUCCESS == flag:
		errorLevel = flag
		Parser.disableConsoleEchoes()
	else:
		errorLevel = EOF
		Parser.disableConsoleEchoes()
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
