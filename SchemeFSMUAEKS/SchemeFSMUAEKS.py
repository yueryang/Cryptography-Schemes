from os import chdir, makedirs, name, sep
from os.path import abspath, basename, dirname, exists, isfile, isdir, join, split, splitext
from sys import argv, exit
from codecs import lookup
from getpass import getpass
from hashlib import sha3_256
try:
	from numpy import arange, asarray, concatenate, dot, eye, fill_diagonal, kron, minimum, ndarray, triu_indices, zeros
	from numpy.linalg import lstsq
	from numpy.random import randint
	from sympy import Matrix
except:
	arange, asarray, concatenate, dot, eye, fill_diagonal, kron, minimum, ndarray, triu_indices, zeros, lstsq, randint, Matrix = (None, ) * 14
from time import perf_counter, sleep
try:
	chdir(abspath(dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)
MAXIMUM_ATTEMPT_COUNT = 100


class Parser:
	__SchemeName = "SchemeFSMUAEKS" # splitext(basename(__file__))[0]
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
		print("This is the official implementation of the FS-MUAEKS cryptographic scheme in the Python programming language based on the Python NumPy and SymPy libraries. ")
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

class SchemeFSMUAEKS:
	__DefaultN, __DefaultM, __DefaultQ, __DefaultLS, __DefaultLR = 2, 8, 16, 2, 2
	def __init__(self:object) -> object:
		self.__n, self.__m, self.__q, self.__lS, self.__lR = (None, ) * 5
		self.__B, self.__pkS, self.__skS, self.__pkR, self.__skR = (None, ) * 5
		self.__Ft, self.__cipherText, self.__trapdoor = (None, ) * 3
	def __requireSetup(self:object) -> None:
		if not all(isinstance(value, int) for value in (self.__n, self.__m, self.__q, self.__lS, self.__lR)):
			raise RuntimeError("The scheme has not been set up. ")
	def __H1(self:object, message:ndarray, m:int) -> ndarray:
		hashValue = sha3_256(message.tobytes()).digest()
		hashString = "".join(format(byte, "08b") for byte in hashValue)
		hashList = [int(bit) for bit in hashString][:(m * (m - 1)) >> 1]
		hashList += [0] * (((m * (m - 1)) >> 1) - len(hashList))
		hashArray = eye(m, dtype = "int")
		hashArray[triu_indices(m, k = 1)] = hashList
		return hashArray
	def __TrapGen(self:object) -> tuple:
		self.__requireSetup()
		n, m, q = self.__n, self.__m, self.__q
		g = (1 << arange(0, m // (n << 1))).reshape((1, m // (n << 1)))
		G = kron(eye(n, dtype = "int"), g) % q
		B = randint(q, size = (n, m >> 1))
		R = randint(2, size = (m >> 1, m >> 1))
		A0i = concatenate((B, (dot(B, R) % q + G) % q), axis = 1)
		Tg = zeros((m // (n << 1), m // (n << 1)), dtype = "int")
		fill_diagonal(Tg, 2)
		fill_diagonal(Tg[1:], -1)
		TG = kron(eye(n, dtype = "int"), Tg) % q
		GTranspose = G.T
		TAa = concatenate(((eye(m >> 1, dtype = "int") + dot(dot(R, GTranspose) % q, B) % q) % q, dot(-R, TG) % q), axis = 1)
		TAb = concatenate((dot((-GTranspose) % q, B) % q, TG), axis = 1)
		return (A0i, concatenate((TAa, TAb), axis = 0))
	def __ExtBasis(self:object, FB0:ndarray, TB0:ndarray, B0:ndarray, q:int) -> ndarray:
		W = lstsq(B0, FB0, rcond = None)[0].astype("int") % q
		return concatenate((
			concatenate((TB0, W), axis = 1),
			concatenate((zeros((W.shape[1], TB0.shape[1]), dtype = "int"), eye(W.shape[1], dtype = "int")), axis = 1)
		), axis = 0)
	def __SampleLeft(self:object, A:ndarray, C_u:ndarray, q:int) -> ndarray:
		ES = zeros((A.shape[1], C_u.shape[1]), dtype = "int")
		for column in range(C_u.shape[1]):
			ES[:, column] = lstsq(A, C_u[:, column], rcond = None)[0].astype("int") % q
		return ES
	def __hashMatrix(self:object, pkS:tuple, pkR:tuple, value:ndarray) -> ndarray:
		message = concatenate((*pkS, *pkR, value), axis = 1)
		return asarray(Matrix(self.__H1(message, self.__m)).inv()).astype("int") % self.__q
	def Setup(self:object, n:int = __DefaultN, m:int = __DefaultM, q:int = __DefaultQ, lS:int = __DefaultLS, lR:int = __DefaultLR) -> tuple:
		if not all(isinstance(value, int) and value >= 1 for value in (n, m, lS, lR)) or not isinstance(q, int) or q <= 1:
			raise ValueError("The parameters n, m, q, lS, and lR must be positive integers, and q must be greater than one. ")
		if m % (n << 1):
			raise ValueError("The parameters n and m must satisfy 2n | m. ")
		self.__n, self.__m, self.__q, self.__lS, self.__lR = n, m, q, lS, lR
		self.__B = randint(q, size = (6, n, m))
		self.__pkS, self.__skS, self.__pkR, self.__skR = (None, ) * 4
		self.__Ft, self.__cipherText, self.__trapdoor = (None, ) * 3
		return (n, m, q, lS, lR, self.__B)
	def KeyGenS(self:object) -> tuple:
		self.__requireSetup()
		A, TA = self.__TrapGen()
		US = randint(self.__q, size = (self.__n, self.__n))
		DA = randint(self.__q, size = (self.__n, self.__m))
		AW = randint(self.__q, size = (self.__n, self.__m))
		self.__pkS, self.__skS = (A, US, DA, AW), TA
		return (self.__pkS, self.__skS)
	def KeyGenR(self:object) -> tuple:
		self.__requireSetup()
		B0, TB0 = self.__TrapGen()
		UR = randint(self.__q, size = (self.__n, self.__n))
		DB = randint(self.__q, size = (self.__n, self.__m))
		BW = randint(self.__q, size = (self.__n, self.__m))
		self.__pkR, self.__skR = (B0, UR, DB, BW), TB0
		return (self.__pkR, self.__skR)
	def KeyUpdate(self:object) -> tuple:
		self.__requireSetup()
		if self.__pkR is None or self.__skR is None:
			raise RuntimeError("The receiver keys have not been generated. ")
		B0, B, q = self.__pkR[0], self.__B, self.__q
		F001 = concatenate((B0, B[0], B[2], B[5]), axis = 1)
		F01 = concatenate((B0, B[0], B[3]), axis = 1)
		F1 = concatenate((B0, B[1]), axis = 1)
		F011 = concatenate((B0, B[0], B[3], B[5]), axis = 1)
		F101 = concatenate((B0, B[1], B[2], B[5]), axis = 1)
		F11 = concatenate((B0, B[1], B[3]), axis = 1)
		F111 = concatenate((B0, B[1], B[3], B[5]), axis = 1)
		F = (F001, F01, F1, F011, F101, F11, F111)
		T001 = self.__ExtBasis(F001, self.__skR, B0, q)
		T01 = self.__ExtBasis(F01, self.__skR, B0, q)
		T1 = self.__ExtBasis(F1, self.__skR, B0, q)
		T011 = self.__ExtBasis(F011, self.__skR, B0, q)
		T101 = self.__ExtBasis(F101, self.__skR, B0, q)
		T11 = self.__ExtBasis(F11, self.__skR, B0, q)
		T111 = self.__ExtBasis(F111, self.__skR, B0, q)
		forwardSecretKeys = ((T001, T01, T1), (T01, T1), (T011, T1), (T1, ), (T101, T11), (T11, ), (T111, ))
		index = randint(len(F))
		self.__Ft = F[index]
		return (forwardSecretKeys[index], self.__Ft)
	def Encryption(self:object) -> tuple:
		self.__requireSetup()
		if any(value is None for value in (self.__pkS, self.__skS, self.__pkR, self.__Ft)):
			raise RuntimeError("The sender keys, receiver keys, and forward key must be generated before encryption. ")
		n, m, q, lS = self.__n, self.__m, self.__q, self.__lS
		A, US, DA, AW = self.__pkS
		DB, BW = self.__pkR[2], self.__pkR[3]
		EW, SS, ck = randint(q, size = (m, lS)), randint(q, size = (n, lS)), randint(q, size = (n, 1))
		hashMatrix = self.__hashMatrix(self.__pkS, self.__pkR, ck)
		Cw = (EW + dot((dot(AW, hashMatrix) % q).T, SS) % q) % q
		RA = (randint(2, size = (m, m)) << 1) - 1
		RC = (randint(2, size = (m, m)) << 1) - 1
		Ca = (dot(A.T, SS) % q + dot(RA, EW) % q) % q
		Cc = (dot(DA.T, SS) % q + dot(RC, EW) % q) % q
		RB = (randint(2, size = (self.__Ft.shape[1], m)) << 1) - 1
		EU = randint(q, size = (n, lS))
		Cb = (dot(self.__Ft.T, SS) % q + dot(RB, EW) % q) % q
		Cu = (dot(US, SS) % q + EU) % q
		ES = self.__SampleLeft(A, Cu, q)
		self.__cipherText = (Cw, Ca, Cb, Cc, ES)
		return self.__cipherText
	def Trapdoor(self:object) -> tuple:
		self.__requireSetup()
		if any(value is None for value in (self.__pkS, self.__pkR, self.__skR, self.__Ft)):
			raise RuntimeError("The sender keys, receiver keys, and forward key must be generated before trapdoor generation. ")
		n, m, q, lR = self.__n, self.__m, self.__q, self.__lR
		A, US, DA, AW = self.__pkS
		DB, BW = self.__pkR[2], self.__pkR[3]
		SR, EDoubleW, tk = randint(q, size = (n, lR)), randint(q, size = (m, lR)), randint(q, size = (n, 1))
		hashMatrix = self.__hashMatrix(self.__pkS, self.__pkR, tk)
		Tw = (EDoubleW + dot((dot(BW, hashMatrix) % q).T, SR) % q) % q
		RDoubleA = (randint(2, size = (m, m)) << 1) - 1
		RDoubleB = (randint(2, size = (self.__Ft.shape[1], m)) << 1) - 1
		RDoubleC = (randint(2, size = (m, m)) << 1) - 1
		Ta = (dot(A.T, SR) % q + dot(RDoubleA, EDoubleW) % q) % q
		Tb = (dot(self.__Ft.T, SR) % q + dot(RDoubleB, EDoubleW) % q) % q
		Tc = (dot(DB.T, SR) % q + dot(RDoubleC, EDoubleW) % q) % q
		EDoubleU = randint(q, size = (n, lR))
		Tu = (dot(US, SR) % q + EDoubleU) % q
		ER = self.__SampleLeft(self.__Ft, Tu, q)
		self.__trapdoor = (Tw, Ta, Tb, Tc, ER)
		return self.__trapdoor
	def Test(self:object) -> bool:
		self.__requireSetup()
		if self.__cipherText is None or self.__trapdoor is None:
			return False
		Cb, ES = self.__cipherText[2], self.__cipherText[4]
		Ta, ER = self.__trapdoor[1], self.__trapdoor[4]
		value = (dot(ER.T, Cb) % self.__q - dot(Ta.T, ES) % self.__q) % self.__q
		centeredValue = minimum(value, self.__q - value)
		return bool((centeredValue < self.__q >> 2).all())
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


def __conductScheme(parameter:tuple|list|dict, run:int|None = None, isVerbose:bool = False) -> tuple:
	nString, mString, qString, lSString, lRString, runString = ("N/A", ) * 6
	isSystemValid, isSchemeCorrect, isCompleted = (False, ) * 3
	timeSetup, timeKeyGenS, timeKeyGenR, timeKeyUpdate, timeEncryption, timeTrapdoor, timeTest = ("N/A", ) * 7
	sizeParams, sizePkS, sizeSkS, sizePkR, sizeSkR, sizeForwardKey, sizeCipherText, sizeTrapdoor = ("N/A", ) * 8
	if isinstance(parameter, (tuple, list)) and len(parameter) >= 5:
		n, m, q, lS, lR = parameter[:5]
	elif isinstance(parameter, dict):
		n, m, q, lS, lR = tuple(parameter.get(key) for key in ("n", "m", "q", "lS", "lR"))
	else:
		n, m, q, lS, lR = (None, ) * 5
	if all(isinstance(value, int) for value in (n, m, q, lS, lR)):
		nString, mString, qString, lSString, lRString = n, m, q, lS, lR
	if isinstance(run, int) and run >= 1:
		runString = run
	if isVerbose is not False:
		print("Parameters: (n = {0}, m = {1}, q = {2}, lS = {3}, lR = {4})".format(nString, mString, qString, lSString, lRString))
		print("run:", runString)
	try:
		if not all(isinstance(value, int) for value in (n, m, q, lS, lR)):
			raise ValueError("The parameters are invalid. ")
		scheme = SchemeFSMUAEKS()
		startTime = perf_counter()
		params = scheme.Setup(n, m, q, lS, lR)
		timeSetup = perf_counter() - startTime
		isSystemValid = True
		startTime = perf_counter()
		pkS, skS = scheme.KeyGenS()
		timeKeyGenS = perf_counter() - startTime
		startTime = perf_counter()
		pkR, skR = scheme.KeyGenR()
		timeKeyGenR = perf_counter() - startTime
		startTime = perf_counter()
		forwardSecretKey, forwardKey = scheme.KeyUpdate()
		timeKeyUpdate = perf_counter() - startTime
		startTime = perf_counter()
		cipherText = scheme.Encryption()
		timeEncryption = perf_counter() - startTime
		startTime = perf_counter()
		trapdoor = scheme.Trapdoor()
		timeTrapdoor = perf_counter() - startTime
		startTime = perf_counter()
		isSchemeCorrect = scheme.Test()
		timeTest = perf_counter() - startTime
		sizeParams = scheme.getLengthOf(params)
		sizePkS, sizeSkS = scheme.getLengthOf(pkS), scheme.getLengthOf(skS)
		sizePkR, sizeSkR = scheme.getLengthOf(pkR), scheme.getLengthOf(skR)
		sizeForwardKey = scheme.getLengthOf((forwardSecretKey, forwardKey))
		sizeCipherText, sizeTrapdoor = scheme.getLengthOf(cipherText), scheme.getLengthOf(trapdoor)
		isCompleted = True
		if isVerbose is not False:
			print("Is the system valid? Yes. ")
			print("Is the scheme correct? {0}. ".format("Yes" if isSchemeCorrect else "No"))
			print("Time:", (timeSetup, timeKeyGenS, timeKeyGenR, timeKeyUpdate, timeEncryption, timeTrapdoor, timeTest))
			print("Space:", (sizeParams, sizePkS, sizeSkS, sizePkR, sizeSkR, sizeForwardKey, sizeCipherText, sizeTrapdoor))
			print()
	except BaseException as e:
		if isVerbose is not False:
			print("Is the system valid? No. The execution failed due to {0}. ".format(repr(e)))
			print()
	return ([
		Parser.getSchemeName(), nString, mString, qString, lSString, lRString, runString,
		isSystemValid, isSchemeCorrect,
		timeSetup, timeKeyGenS, timeKeyGenR, timeKeyUpdate, timeEncryption, timeTrapdoor, timeTest,
		sizeParams, sizePkS, sizeSkS, sizePkR, sizeSkR, sizeForwardKey, sizeCipherText, sizeTrapdoor
	], isCompleted)

def conductScheme(parameter:tuple|list|dict, run:int|None = None, isVerbose:bool = False) -> list:
	result, isCompleted = __conductScheme(parameter, run, isVerbose)
	attempt = 1
	while isCompleted and not result[8] and attempt < MAXIMUM_ATTEMPT_COUNT:
		result, isCompleted = __conductScheme(parameter, run, isVerbose)
		attempt += 1
	return result

def main() -> int:
	flag, encoding, outputFilePath, decimalPlace, isVerbose, runCount, waitingTime, overwritingConfirmed = Parser.parse(argv)
	if flag > EXIT_SUCCESS and flag > EOF:
		if any((
			arange is None, asarray is None, concatenate is None, dot is None, eye is None, fill_diagonal is None, 
			kron is None, ndarray is None, triu_indices is None, zeros is None, lstsq is None, randint is None, Matrix is None
		)):
			Parser.disableConsoleEchoes()
			print("The runtime environment of the Python NumPy and SymPy libraries is not correctly configured. ")
			print("Please install the libraries via the active Python package manager (e.g., pip). ")
			errorLevel = EOF
		else:
			outputFilePath, overwritingConfirmed = Parser.checkOverwriting(outputFilePath, overwritingConfirmed)
			Parser.disableConsoleEchoes()
			print("The execution has started. ")
			print()
			
			# Parameters #
			parameters = ((2, 8, 16, 2, 2), (4, 16, 16, 4, 2))
			queries = ("scheme", "n", "m", "q", "lS", "lR", "runCount")
			validators = ("isSystemValid", "isSchemeCorrect")
			metrics = (
				"Setup (s)", "KeyGenS (s)", "KeyGenR (s)", "KeyUpdate (s)", "Encryption (s)", "Trapdoor (s)", "Test (s)",
				"params (B)", "pkS (B)", "skS (B)", "pkR (B)", "skR (B)", "forwardKey (B)", "cipherText (B)", "trapdoor (B)"
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