from os import chdir, makedirs, name, sep
from os.path import abspath, basename, dirname, exists, isfile, isdir, join, split, splitext
from sys import argv, exit
try:
	from charm.toolbox.pairinggroup import PairingGroup, G1, GT, ZR, pair, pc_element as Element
except:
	PairingGroup, G1, GT, ZR, pair, Element = (None, ) * 6
from codecs import lookup
from getpass import getpass
from hashlib import md5, sha1, sha3_224, sha3_256, sha3_384, sha3_512
from random import shuffle
from time import perf_counter, sleep
from warnings import filterwarnings
filterwarnings(
	"ignore", category = DeprecationWarning, 
	message = "^Curve \'SS[0-9]+\' provides only ~80-bit security, which is below the 128-bit minimum recommended by NIST. Use \'BN254\' \\(128-bit\\) or stronger for production use\\.$"
)
try:
	chdir(abspath(dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)


class Parser:
	__SchemeName = "SchemeFuzzyME" # splitext(basename(__file__))[0]
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
		print("This is a possible implementation of the Fuzzy-ME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ")
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

class SchemeFuzzyME:
	__DefaultN, __DefaultD = 30, 10
	def __init__(self:object, group:None|PairingGroup = None) -> object: # This scheme is only applicable to symmetric groups of prime orders. 
		self.__group = group if isinstance(group, PairingGroup) else PairingGroup("SS512", secparam = 512)
		try:
			pair(self.__group.random(G1), self.__group.random(G1))
		except:
			self.__group = PairingGroup("SS512", secparam = self.__group.secparam)
			print("Init: This scheme is only applicable to symmetric groups of prime orders. The curve name has been defaulted to \"SS512\". ")
		if self.__group.secparam < 1:
			self.__group = PairingGroup(self.__group.groupType())
			print("Init: The securtiy parameter should be a positive integer, but it is not, which has been defaulted to {0}. ".format(self.__group.secparam))
		self.__n = SchemeFuzzyME.__DefaultN
		self.__d = SchemeFuzzyME.__DefaultD
		self.__mpk = None
		self.__msk = None
		self.__flag = False # to indicate whether it has already set up
	def __product(self:object, elements:object) -> Element:
		try:
			if isinstance(elements, (tuple, list)):
				result = elements[0]
				for element in elements[1:]:
					result *= element
			else:
				it = iter(elements)
				result = next(it)
				for element in it:
					result *= element
			return result if isinstance(result, Element) else self.__group.init(ZR, result)
		except Exception:
			return self.__group.init(ZR, 1)
	def __computePolynomial(self:object, x:Element|int|float, coefficients:tuple|list) -> Element|int|float|None:
		if isinstance(coefficients, (tuple, list)) and coefficients and (
			isinstance(x, Element) and all(isinstance(coefficient, Element) and coefficient.type == x.type for coefficient in coefficients)
			or isinstance(x, (int, float)) and all(isinstance(coefficient, (int, float)) for coefficient in coefficients)
		):
			n, eleResult = len(coefficients) - 1, coefficients[0]
			for i in range(1, n):
				eResult = x
				for _ in range(i - 1):
					eResult *= x
				eleResult += coefficients[i] * eResult
			eResult = x
			for _ in range(n - 1):
				eResult *= x
			eleResult += eResult
			return eleResult
		else:
			return None
	def Setup(self:object, n:int = __DefaultN, d:int = __DefaultD) -> tuple: # $\textbf{Setup}(n, d) \to (\textit{mpk}, \textit{msk})$
		# Checks #
		self.__flag = False
		if isinstance(n, int) and isinstance(d, int) and 2 <= d <= n: # boundary check
			self.__n, self.__d = n, d
		else:
			self.__n, self.__d = SchemeFuzzyME.__DefaultN, SchemeFuzzyME.__DefaultD
			print(
				"Setup: The variables $n$ and $d$ should be two positive integers satisfying $2 \\leqslant d \\leqslant n$, but they are not, "
				+ "which have been defaulted to ${0}$ and ${1}$, respectively. ".format(SchemeFuzzyME.__DefaultN, SchemeFuzzyME.__DefaultD)
			)
		
		# Scheme #
		g = self.__group.init(G1, 1) # $g \gets 1_{\mathbb{G}_1}$
		g2, g3 = self.__group.random(G1), self.__group.random(G1) # generate $g_2, g_3 \in \mathbb{G}_1$ randomly
		tVec = tuple(self.__group.random(G1) for _ in range(n + 1)) # generate $\vec{t} = (t_1, t_2, \cdots, t_{n + 1}) \in \mathbb{G}_1^{n + 1}$ randomly
		lVec = tuple(self.__group.random(G1) for _ in range(n + 1)) # generate $\vec{l} = (l_1, l_2, \cdots, l_{n + 1}) \in \mathbb{G}_1^{n + 1}$ randomly
		alpha, beta, theta1, theta2, theta3, theta4 = self.__group.random(ZR, 6) # generate $\alpha, \beta, \theta_1, \theta_2, \theta_3, \theta_4 \in \mathbb{Z}_r$ randomly
		g1 = g ** alpha # $g_1 \gets g^\alpha$
		eta1 = g ** theta1 # $\eta_1 \gets g^{\theta_1}$
		eta2 = g ** theta2 # $\eta_2 \gets g^{\theta_2}$
		eta3 = g ** theta3 # $\eta_3 \gets g^{\theta_3}$
		eta4 = g ** theta4 # $\eta_4 \gets g^{\theta_4}$
		Y1 = pair(g1, g2) ** (theta1 * theta2) # $Y_1 \gets \hat{e}(g_1, g_2)^{\theta_1 \theta_2}$
		Y2 = pair(g3, g ** beta) ** (theta1 * theta2) # $Y_2 \gets \hat{e}(g_3, g^\beta)^{\theta_1 \theta_2}$
		H1 = lambda x:self.__group.hash(x, G1) # $H_1: \{0, 1\}^* \to \mathbb{G}_1$
		self.__mpk = (g1, g2, g3, Y1, Y2, tVec, lVec, eta1, eta2, eta3, eta4, H1) # $ \textit{mpk} \gets (g_1, g_2, g_3, Y_1, Y_2, \vec{t}, \vec{l}, \eta_1, \eta_2, \eta_3, \eta_4, H_1)$
		self.__msk = (alpha, beta, theta1, theta2, theta3, theta4) # $\textit{msk} \gets (\alpha, \beta, \theta_1, \theta_2, \theta_3, \theta_4)$
		
		# Flag #
		self.__flag = True
		return (self.__mpk, self.__msk) # \textbf{return} $(\textit{mpk}, \textit{msk})$
	def EKGen(self:object, SA:tuple) -> tuple: # $\textbf{EKGen}(S_A) \to \textit{ek}_{S_A}$
		# Checks #
		if not self.__flag:
			print("EKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``EKGen`` subsequently. ")
			self.Setup()
		if isinstance(SA, tuple) and len(SA) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in SA): # hybrid check
			S_A = SA
		else:
			S_A = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("EKGen: The variable $S_A$ should be a tuple containing $n$ elements of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		g3, lVec = self.__mpk[2], self.__mpk[6]
		beta, theta1, theta2 = self.__msk[1], self.__msk[2], self.__msk[3]
		
		# Scheme #
		g = self.__group.init(G1, 1) # $g \gets 1_{\mathbb{G}_1}$
		Delta = lambda i, S, x:self.__product(tuple((x - j) / (i - j) for j in S if j != i)) # $\Delta_{i, S}(x) := \prod\limits_{j \in S, j \neq i} \frac{x - j}{i - j}$
		N = tuple(range(1, self.__n + 2)) # $N \gets (1, 2, \cdots, n + 1)$
		H = lambda x:g3 ** (x ** self.__n) * self.__product(tuple(lVec[i] ** Delta(i, N, x) for i in range(self.__n + 1))) # $H: x \to g_3^{x^n} \prod\limits_{i = 1}^{n + 1} l_i^{\Delta_{i, N}(x)}$
		coefficients = (beta, ) + tuple(self.__group.random(ZR) for _ in range(self.__d - 2)) + (self.__group.init(ZR, 1), )
		q = lambda x:self.__computePolynomial(x, coefficients) # generate a $(d - 1)$ degree polynominal $q(x)$ s.t. $q(0) = \beta$ randomly
		rVec = tuple(self.__group.random(ZR) for _ in S_A) # generate $\vec{r} = (r_1, r_2, \cdots, r_n) \in \mathbb{Z}_r^n$ randomly
		EVec = tuple(g3 ** (q(S_A[i]) * theta1 * theta2) * H(S_A[i]) ** rVec[i] for i in range(len(S_A))) # $E_i \gets g_3^{q(a_i) \theta_1 \theta_2} H(a_i)^{r_i}, \forall i \in \{1, 2, \cdots, n\}$
		eVec = tuple(g ** rVec[i] for i in range(len(S_A))) # $e_i \gets g^{r_i}, \forall i \in \{1, 2, \cdots, n\}$
		ek_S_A = (EVec, eVec) # $\textit{ek}_{S_A} \gets \{E_i, e_i\}_{a_i \in S_A}$
		
		# Return #
		return ek_S_A # \textbf{return} $\textit{ek}_{S_A}$
	def DKGen(self:object, SB:tuple, PA:tuple) -> tuple: # $\textbf{DKGen}(\textit{id}_R) \to \textit{dk}_{\textit{id}_R}$
		# Checks #
		if not self.__flag:
			print("DKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``DKGen`` subsequently. ")
			self.Setup()
		if isinstance(SB, tuple) and len(SB) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in SB): # hybrid check
			S_B = SB
		else:
			S_B = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("DKGen: The variable $S_B$ should be a tuple containing $n$ elements of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		if isinstance(PA, tuple) and len(PA) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in PA): # hybrid check
			P_A = PA
		else:
			P_A = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("DKGen: The variable $P_A$ should be a tuple containing $n$ elements of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		g2, g3, tVec, lVec = self.__mpk[1], self.__mpk[2], self.__mpk[5], self.__mpk[6]
		alpha, beta, theta1, theta2, theta3, theta4 = self.__msk[0], self.__msk[1], self.__msk[2], self.__msk[3], self.__msk[4], self.__msk[5]
		
		# Scheme #
		g = self.__group.init(G1, 1) # $g \gets 1_{\mathbb{G}_1}$
		Delta = lambda i, S, x:self.__product(tuple((x - j) / (i - j) for j in S if j != i)) # $\Delta_{i, S}(x) := \prod\limits_{j \in S, j \neq i} \frac{x - j}{i - j}$
		N = tuple(range(1, self.__n + 2)) # $N \gets (1, 2, \cdots, n + 1)$
		T = lambda x:g2 ** (x ** self.__n) * self.__product(tuple(tVec[i] ** Delta(i, N, x) for i in range(self.__n + 1))) # $T: x \to g_2^{x^n} \prod\limits_{i = 1}^{n + 1} t_i^{\Delta_{i, N}(x)}$
		H = lambda x:g3 ** (x ** self.__n) * self.__product(tuple(lVec[i] ** Delta(i, N, x) for i in range(self.__n + 1))) # $H: x \to g_3^{x^n} \prod\limits_{i = 1}^{n + 1} l_i^{\Delta_{i, N}(x)}$
		gamma = self.__group.random(ZR) # generate $\gamma \in \mathbb{Z}_r$ randomly
		G_ID = self.__group.random(G1) # generate $G_{\textit{ID}} \in \mathbb{G}_1$ randomly
		coefficientsForF = (alpha, ) + tuple(self.__group.random(ZR) for _ in range(self.__d - 2)) + (self.__group.init(ZR, 1), )
		f = lambda x:self.__computePolynomial(x, coefficientsForF) # generate a $(d - 1)$ degree polynominal $f(x)$ s.t. $f(0) = \alpha$ randomly
		coefficientsForH = (gamma, ) + tuple(self.__group.random(ZR) for _ in range(self.__d - 2)) + (self.__group.init(ZR, 1), )
		h = lambda x:self.__computePolynomial(x, coefficientsForH) # generate a $(d - 1)$ degree polynominal $h(x)$ s.t. $h(0) = \gamma$ randomly
		coefficientsForQPrime = (beta, ) + tuple(self.__group.random(ZR) for _ in range(self.__d - 2)) + (self.__group.init(ZR, 1), )
		qPrime = lambda x:self.__computePolynomial(x, coefficientsForQPrime) # generate a $(d - 1)$ degree polynominal $q'(x)$ s.t. $q'(0) = \beta$ randomly
		k1Vec = tuple(self.__group.random(ZR) for _ in range(self.__n)) # generate $\vec{k}_1 = (k_{1, 1}, k_{1, 2}, \cdots, k_{1, n}) \in \mathbb{Z}_r^n$ randomly
		k2Vec = tuple(self.__group.random(ZR) for _ in range(self.__n)) # generate $\vec{k}_2 = (k_{2, 1}, k_{2, 2}, \cdots, k_{2, n}) \in \mathbb{Z}_r^n$ randomly
		rPrime1Vec = tuple(self.__group.random(ZR) for _ in range(self.__n)) # generate $\vec{r}'_1 = (r'_{1, 1}, r'_{1, 2}, \cdots, r'_{1, n}) \in \mathbb{Z}_r^n$ randomly
		rPrime2Vec = tuple(self.__group.random(ZR) for _ in range(self.__n)) # generate $\vec{r}'_2 = (r'_{2, 1}, r'_{2, 2}, \cdots, r'_{2, n}) \in \mathbb{Z}_r^n$ randomly
		dk_S_B_0 = tuple(g ** (k1Vec[i] * theta1 * theta2 + k2Vec[i] * theta3 * theta4) for i in range(self.__n)) # $\textit{dk}_{S_{B_{0, i}}} \gets g^{k_{1, i} \theta_1 \theta_2 + k_{2, i} \theta_3 \theta_4}, \forall i \in \{1, 2, \cdots, n\}$
		dk_S_B_1 = tuple(
			g2 ** (-f(S_B[i]) * theta2) * G_ID ** (-h(S_B[i]) * theta2) * T(S_B[i]) ** (-k1Vec[i] * theta2) for i in range(self.__n)
		) # $\textit{dk}_{S_{B_{1, i}}} \gets g_2^{-f(b_i) \theta_2} (G_{\textit{ID}})^{-h(b_i) \theta_2} [T(b_i)]^{-k_{1, i} \theta_2}, \forall i \in \{1, 2, \cdots, n\}$
		dk_S_B_2 = tuple(
			g2 ** (-f(S_B[i]) * theta1) * G_ID ** (-h(S_B[i]) * theta1) * T(S_B[i]) ** (-k1Vec[i] * theta1) for i in range(self.__n)
		) # $\textit{dk}_{S_{B_{2, i}}} \gets g_2^{-f(b_i) \theta_1} (G_{\textit{ID}})^{-h(b_i) \theta_1} [T(b_i)]^{-k_{1, i} \theta_1}, \forall i \in \{1, 2, \cdots, n\}$
		dk_S_B_3 = tuple(T(S_B[i]) ** (-k2Vec[i] * theta4) for i in range(self.__n)) # $\textit{dk}_{S_{B_{3, i}}} \gets [T(b_i)]^{-k_{2, i} \theta_4}, \forall i \in \{1, 2, \cdots, n\}$
		dk_S_B_4 = tuple(T(S_B[i]) ** (-k2Vec[i] * theta3) for i in range(self.__n)) # $\textit{dk}_{S_{B_{4, i}}} \gets [T(b_i)]^{-k_{2, i} \theta_3}, \forall i \in \{1, 2, \cdots, n\}$
		dk_S_B = (dk_S_B_0, dk_S_B_1, dk_S_B_2, dk_S_B_3, dk_S_B_4) # $\textit{dk}_{S_B} \gets (\textit{dk}_{S_{B_0}}, \textit{dk}_{S_{B_1}}, \textit{dk}_{S_{B_2}}, \textit{dk}_{S_{B_3}}, \textit{dk}_{S_{B_4}})$
		dk_P_A_0 = tuple(g ** (rPrime1Vec[i] * theta1 * theta2 + rPrime2Vec[i] * theta3 * theta4) for i in range(self.__n)) # $\textit{dk}_{P_{A_{0, i}}} \gets g^{r'_{1, i} \theta_1 \theta_2 + r'_{i, 2} \theta_3 \theta_4}, \forall i \in \{1, 2, \cdots, n\}$
		dk_P_A_1 = tuple(
			g2 ** (-2 * qPrime(P_A[i]) * theta2) * G_ID ** (h(P_A[i]) * theta2) * H(P_A[i]) ** (-rPrime1Vec[i] * theta2) for i in range(self.__n)
		) # $\textit{dk}_{P_{A_{1, i}}} \gets g_2^{-2q'(a_i) \theta_2} (G_{\textit{ID}})^{h(a_i \theta_2)} H(a_i)^{-r'_{1, i} \theta_2}, \forall i \in \{1, 2, \cdots, n\}$
		dk_P_A_2 = tuple(
			g2 ** (-2 * qPrime(P_A[i]) * theta1) * G_ID ** (h(P_A[i]) * theta1) * H(P_A[i]) ** (-rPrime1Vec[i] * theta1) for i in range(self.__n)
		) # $\textit{dk}_{P_{A_{2, i}}} \gets g_2^{-2q'(a_i) \theta_1} (G_{\textit{ID}})^{h(a_i \theta_1)} H(a_i)^{-r'_{1, i} \theta_1}, \forall i \in \{1, 2, \cdots, n\}$
		dk_P_A_3 = tuple(H(P_A[i]) ** (-rPrime2Vec[i] * theta4) for i in range(self.__n)) # $\textit{dk}_{P_{A_{3, i}}} \gets [H(a_i)]^{-r'_{2, i} \theta_4}, \forall i \in \{1, 2, \cdots, n\}$
		dk_P_A_4 = tuple(H(P_A[i]) ** (-rPrime2Vec[i] * theta3) for i in range(self.__n)) # $\textit{dk}_{P_{A_{3, i}}} \gets [H(a_i)]^{-r'_{2, i} \theta_3}, \forall i \in \{1, 2, \cdots, n\}$
		dk_P_A = (dk_P_A_0, dk_P_A_1, dk_P_A_2, dk_P_A_3, dk_P_A_4) # $\textit{dk}_{P_A} \gets (\textit{dk}_{P_{A_0}}, \textit{dk}_{P_{A_1}}, \textit{dk}_{P_{A_2}}, \textit{dk}_{P_{A_3}}, \textit{dk}_{P_{A_4}})$
		dk_SBPA = (dk_S_B, dk_P_A) # $\textit{dk}_{S_B, P_A} \gets (\textit{dk}_{S_B}, \textit{dk}_{P_A})$
		
		# Return #
		return dk_SBPA # \textbf{return} $\textit{dk}_{S_B, P_A}$
	def Encryption(self:object, ekSA:tuple, SA:tuple, PB:tuple, message:Element) -> tuple: # $\textbf{Encryption}(\textit{ek}_{S_A}, S_A, P_B, M) \to \textit{CT}$
		# Checks #
		if not self.__flag:
			print("Encryption: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Encryption`` subsequently. ")
			self.Setup()
		if isinstance(SA, tuple) and len(SA) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in SA): # hybrid check
			S_A = SA
			if isinstance(ekSA, tuple) and len(ekSA) == 2 and isinstance(ekSA[0], tuple) and isinstance(ekSA[1], tuple) and len(ekSA[0]) == len(ekSA[1]) == self.__n: # hybrid check
				ek_S_A = ekSA
			else:
				ek_S_A = self.EKGen(S_A)
				print("Encryption: The variable $\\textit{ek}_{S_A}$ should be a tuple containing 2 tuples, but it is not, which has been generated accordingly. ")
		else:
			S_A = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("Encryption: The variable $S_A$ should be a tuple containing $n$ elements of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
			ek_S_A = self.EKGen(S_A)
			print("Encryption: The variable $\\textit{ek}_{S_A}$ has been generated accordingly. ")
		if isinstance(PB, tuple) and len(PB) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in PB): # hybrid check
			P_B = PB
		else:
			P_B = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("Encryption: The variable $P_B$ should be a tuple containing $n$ elements of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		if isinstance(message, Element) and message.type == GT: # type check
			M = message
		else:
			M = self.__group.random(GT)
			print("Encryption: The variable $M$ should be an element of $\\mathbb{G}_T$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		g2, g3, Y1, Y2, tVec, lVec, eta1, eta2, eta3, eta4, H1 = self.__mpk[1], self.__mpk[2], self.__mpk[3], self.__mpk[4], self.__mpk[5], self.__mpk[6], self.__mpk[7], self.__mpk[8], self.__mpk[9], self.__mpk[10], self.__mpk[11]
		EVec, eVec = ek_S_A
		
		# Scheme #
		g = self.__group.init(G1, 1) # $g \gets 1_{\mathbb{G}_1}$
		Delta = lambda i, S, x:self.__product(tuple((x - j) / (i - j) for j in S if j != i)) # $\Delta_{i, S}(x) := \prod\limits_{j \in S, j \neq i} \frac{x - j}{i - j}$
		N = tuple(range(1, self.__n + 2)) # $N \gets (1, 2, \cdots, n + 1)$
		T = lambda x:g2 ** (x ** self.__n) * self.__product(tuple(tVec[i] ** Delta(i, N, x) for i in range(self.__n + 1))) # $T: x \to g_2^{x^n} \prod\limits_{i = 1}^{n + 1} t_i^{\Delta_{i, N}(x)}$
		H = lambda x:g3 ** (x ** self.__n) * self.__product(tuple(lVec[i] ** Delta(i, N, x) for i in range(self.__n + 1))) # $H: x \to g_3^{x^n} \prod\limits_{i = 1}^{n + 1} l_i^{\Delta_{i, N}(x)}$
		s, s1, s2, tau = self.__group.random(ZR, 4) # generate $s, s_1, s_2, \tau \in \mathbb{Z}_r$ randomly
		K_s = Y1 ** s # $K_s \gets Y_1^s$
		K_l = Y2 ** s * pair(g3, g ** (-tau)) # $K_l \gets Y_2^s \cdot \hat{e}(g_3, g^{-\tau})$
		C0 = M * K_s * K_l # $C_0 \gets M \cdot K_s \cdot K_l$
		C1 = eta1 ** (s - s1) # $C_1 \gets \eta_1^{s - s_1}$
		C2 = eta2 ** s1 # $C_2 \gets \eta_2^{s_1}$
		C3 = eta3 ** (s - s2) # $C_3 \gets \eta_3^{s - s_2}$
		C4 = eta4 ** s2 # $C_4 \gets \eta_4^{s_2}$
		C1Vec = tuple(T(P_B[i]) ** s for i in range(len(P_B))) # $C_{1, i} \gets T(b_i)^s, \forall b_i \in P_B$
		C2Vec = tuple(H(S_A[i]) ** s for i in range(len(S_A))) # $C_{2, i} \gets H(a_i)^s, \forall a_i \in S_A$
		coefficients = (tau, ) + tuple(self.__group.random(ZR) for _ in range(self.__d - 2)) + (self.__group.init(ZR, 1), )
		l = lambda x:self.__computePolynomial(x, coefficients) # generate a $(d - 1)$ degree polynominal $l(x)$ s.t. $l(0) = \tau$ randomly
		xiVec = tuple(self.__group.random(ZR) for _ in range(self.__n)) # generate $\vec{\xi} = (\xi_1, \xi_2, \cdots, \xi_n) \in \mathbb{Z}_r^n$ randomly
		chiVec = tuple(self.__group.random(ZR) for _ in range(self.__n)) # generate $\vec{\chi} = (\chi_1, \chi_2, \cdots, \chi_n) \in \mathbb{Z}_r^n$ randomly
		C3Vec = tuple(eVec[i] * g ** xiVec[i] for i in range(self.__n)) # $C_{3, i} \gets e_i \cdot g^{\xi_i}, \forall i \in \{1, 2, \cdots, n\}$
		C4Vec = tuple(g ** chiVec[i] for i in range(self.__n)) # $C_{4, i} \gets g^{\chi_i}, \forall i \in \{1, 2, \cdots, n\}$
		C5Vec = tuple(EVec[i] ** s * g3 ** l(S_A[i]) * H(S_A[i]) ** (s * xiVec[i]) * H1(
			self.__group.serialize(C0) + self.__group.serialize(C1) + self.__group.serialize(C2) + self.__group.serialize(C3) + self.__group.serialize(C4)
			+ self.__group.serialize(C1Vec[i]) + self.__group.serialize(C2Vec[i]) + self.__group.serialize(C3Vec[i]) + self.__group.serialize(C4Vec[i])
		) for i in range(self.__n)) # $C_{5, i} \gets E_i^s \cdot g_3^{l(a_i)} H(a_i)^{s \cdot \xi_i} \cdot H_1(C_0 || C_1 || C_2 || C_3 || C_4 || C_{1, i} || C_{2, i} || C_{3, i} || C_{4, i})^{\chi_i}$
		CT = (C0, C1, C2, C3, C4, C1Vec, C2Vec, C3Vec, C4Vec, C5Vec) # $\textit{CT} \gets (C_0, C_1, C_2, C_3, C_4, \vec{C}_1, \vec{C}_2, \vec{C}_3, \vec{C}_4, \vec{C}_5)$
		
		# Return #
		return CT # \textbf{return} $\textit{CT}$
	def Decryption(self:object, dkSBPA:tuple, SA:tuple, PA:tuple, SB:tuple, PB:tuple, cipherText:tuple) -> Element|bool: # $\textbf{Decryption}(\textit{dk}_{S_B, P_A}, S_A, P_A, S_B, P_B, \textit{CT}) \to M$
		# Checks #
		if not self.__flag:
			print("Decryption: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Decryption`` subsequently. ")
			self.Setup()
		if (
			isinstance(SA, tuple) and isinstance(PA, tuple) and isinstance(SB, tuple) and isinstance(PB, tuple) and len(SA) == len(PA) == len(SA) == len(SB) == self.__n
			and all(isinstance(ele, Element) and ele.type == ZR for ele in SA) and all(isinstance(ele, Element) and ele.type == ZR for ele in PA)
			and all(isinstance(ele, Element) and ele.type == ZR for ele in SB) and all(isinstance(ele, Element) and ele.type == ZR for ele in PB)
		): # hybrid check
			S_A, P_A, S_B, P_B = SA, PA, SB, PB
			if (
				isinstance(dkSBPA, tuple) and len(dkSBPA) == 2 and isinstance(dkSBPA[0], tuple) and isinstance(dkSBPA[1], tuple) and len(dkSBPA[0]) == len(dkSBPA[1]) == 5
				and all(isinstance(ele, tuple) and len(ele) == self.__n for ele in dkSBPA[0]) and all(isinstance(ele, tuple) and len(ele) == self.__n for ele in dkSBPA[1])
			): # hybrid check
				dk_SBPA = dkSBPA
			else:
				dk_SBPA = self.DKGen(S_B, P_A)
				print("Decryption: The variable $\\textit{dk}_{S_B, P_A}$ should be a tuple containing 2 tuples, but it is not, which has been generated accordingly. ")
		else:
			S_A, P_A = tuple(self.__group.random(ZR) for _ in range(self.__n)), tuple(self.__group.random(ZR) for _ in range(self.__n))
			S_B, P_B = tuple(self.__group.random(ZR) for _ in range(self.__n)), tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("Decryption: Each of the variables $S_A$, $P_A$, $S_B$, and $P_B$ should be a tuple containing 4 elements of $\\mathbb{Z}_r$, but at least one of them is not, all of which have been generated randomly. ")
			dk_SBPA = self.DKGen(S_B, P_A)
			print("Decryption: The variable $\\textit{dk}_{S_B, P_A}$ has been generated accordingly. ")
		if isinstance(cipherText, tuple) and len(cipherText) == 10 and all(isinstance(ele, Element) for ele in cipherText[:5]) and all(isinstance(ele, tuple) and len(ele) == self.__n for ele in cipherText[5:]): # hybrid check
			CT = cipherText
		else:
			CT = self.Enc(self.EKGen(S_A), S_A, P_B, self.__group.random(GT))
			print("Decryption: The variable $\\textit{CT}$ should be a tuple containing 5 elements and 5 tuples, but it is not, which has been generated randomly. ")
		
		# Unpack #
		H1 = self.__mpk[11]
		dk_S_B, dk_P_A = dk_SBPA
		dk_S_B_0, dk_S_B_1, dk_S_B_2, dk_S_B_3, dk_S_B_4 = dk_S_B
		dk_P_A_0, dk_P_A_1, dk_P_A_2, dk_P_A_3, dk_P_A_4 = dk_P_A
		C0, C1, C2, C3, C4, C1Vec, C2Vec, C3Vec, C4Vec, C5Vec = CT
		
		# Scheme #
		WAPrime = set(S_A).intersection(P_A) # $W'_A \gets S_A \cap P_A$
		WBPrime = set(S_B).intersection(P_B) # $W'_B \gets S_B \cap P_B$
		if len(WAPrime) >= self.__d and len(WBPrime) >= self.__d: # \textbf{if} $|W'_A| \leqslant d \land |W'_B| \leqslant d$ \textbf{then}
			WA = tuple(WAPrime)[:self.__d] # \quad generate $W_A \subset W'_A$ s.t. $|W_A| = d$ randomly
			WB = tuple(WBPrime)[:self.__d] # \quad generate $W_B \subset W'_B$ s.t. $|W_B| = d$ randomly
			g = self.__group.init(G1, 1) # \quad$g \gets 1_{\mathbb{G}_1}$
			Delta = lambda i, S, x:self.__product(tuple((x - j) / (i - j) for j in S if j != i)) # \quad$\Delta_{i, S}(x) := \prod\limits_{j \in S, j \neq i} \frac{x - j}{i - j}$
			KsPrime = self.__product(tuple(( # \quad$K'_s \gets \prod\limits_{b_i \in W_B} (
				pair(C1Vec[i], dk_S_B_0[i]) * pair(C1, dk_S_B_1[i]) * pair(C2, dk_S_B_2[i]) # \hat{e}(C_{1, i}, \textit{dk}_{S_{B_{0, i}}}) \hat{e}(C_1, \textit{dk}_{S_{B_{1, i}}}) \hat{e}(C_2, \textit{dk}_{S_{B_{2, i}}})
				* pair(C3, dk_S_B_3[i]) * pair(C4, dk_S_B_4[i]) # \hat{e}(C_3, \textit{dk}_{S_{B_{3, i}}}) \hat{e}(C_4, \textit{dk}_{S_{B_{4, i}}})
			) ** Delta(S_B[i], WB, 0) for i in range(self.__n))) # )^{\Delta_{b_i, W_B}(0)}$
			CTVec = tuple(
				(
					self.__group.serialize(C0) + self.__group.serialize(C1) + self.__group.serialize(C2) + self.__group.serialize(C3) + self.__group.serialize(C4)
					+ self.__group.serialize(C1Vec[i]) + self.__group.serialize(C2Vec[i]) + self.__group.serialize(C3Vec[i]) + self.__group.serialize(C4Vec[i])
				) for i in range(self.__n)
			) # \quad$\textit{CT}_i \gets C_0 || C_1 || C_2 || C_3 || C_4 || C_{1, i} || C_{2, i} || C_{3, i} || C_{4, i}, \forall i \in \{1, 2, \cdots, n\}$
			KlPrime = self.__product(tuple( # \quad$K'_l \gets \prod\limits_{a_i \in W_A} 
				( # \left(
					(pair(C1Vec[i], dk_P_A_0[i]) * pair(C1, dk_P_A_1[i]) * pair(C2, dk_P_A_2[i])) # \frac{\hat{e}(C_{1, i}, \textit{dk}_{P_{A_{0, i}}}) \hat{e}(C_1, \textit{dk}_{P_{A_{1, i}}}) \hat{e}(C_2, \textit{dk}_{P_{A_{i, 2}}})}
					/ (pair(H1(CTVec[i]), C4Vec[i]) # {\hat{e}(H_1(\textit{CT}_i), C_{4, i}) \cdot \hat{e}(C_{3, i}, C_{2, i})}
					* pair(C3Vec[i], C2Vec[i])) * pair(C3, dk_P_A_3[i]) * pair(C4, dk_P_A_4[i]) * pair(C5Vec[i], g) # \cdot \hat{e}(C_3, \textit{dk}_{P_{A_{i, 3}}}) \hat{e}(C_4, \textit{dk}_{P_{A_{i, 4}}}) \hat{e}(C_{5, i}, g)
				) ** Delta(S_A[i], WA, 0) for i in range(self.__n) # \right)^{\Delta_{a_i, W_A}(0)}
			)) # $
			M = C0 * KsPrime * KlPrime # \quad$M \gets C_0 \cdot K'_s \cdot K'_l$
		else: # \textbf{else}
			M = False # \quad$M \gets \perp$
		# \textbf{end if}
		
		# Return #
		return M # \textbf{return} $M$
	def getLengthOf(self:object, obj:Element|int|bytes|tuple|list|set|dict) -> int|str:
		if isinstance(obj, Element):
			return len(self.__group.serialize(obj))
		elif isinstance(obj, int) or callable(obj):
			return (self.__group.secparam + 7) >> 3
		elif isinstance(obj, bytes):
			return len(obj)
		elif isinstance(obj, (tuple, list, set)):
			sizes = tuple(self.getLengthOf(o) for o in obj)
			return sum(sizes) if all(isinstance(size, int) and size >= 1 for size in sizes) else "N/A"
		elif isinstance(obj, dict):
			sizes = tuple(self.getLengthOf(value) for value in obj.values())
			return sum(sizes) if all(isinstance(size, int) and size >= 1 for size in sizes) else "N/A"
		else:
			return "N/A"


def conductScheme(curveParameter:tuple|list|dict|str, n:int = 30, d:int = 10, run:int|None = None, isVerbose:bool = True) -> list:
	# Begin #
	curveName, securityParameter, nString, dString, runString = "N/A", 512, "N/A", "N/A", "N/A" # the default value of the security parameter in the Python Charm-Crypto framework is 512
	isSystemValid, isSchemeCorrect = False, False
	timeSetup, timeEKGen, timeDKGen, timeEncryption, timeDecryption = ("N/A", ) * 5
	sizeZR, sizeG1G2, sizeGT = ("N/A", ) * 3
	sizeMpk, sizeMsk, sizeEkSA, sizeDkSBPA, sizeCT = ("N/A", ) * 5
	
	# Checks #
	if isinstance(curveParameter, (tuple, list)):
		if len(curveParameter) >= 1 and isinstance(curveParameter[0], str) and curveParameter[0].isalnum():
			curveName = curveParameter[0]
		if len(curveParameter) >= 2 and isinstance(curveParameter[1], int) and curveParameter[1] >= 1:
			securityParameter = curveParameter[1]
	elif isinstance(curveParameter, dict):
		if "curveName" in curveParameter and isinstance(curveParameter["curveName"], str) and curveParameter["curveName"].isalnum():
			curveName = curveParameter["curveName"]
		if "securityParameter" in curveParameter and isinstance(curveParameter["securityParameter"], int) and curveParameter["securityParameter"] >= 1:
			securityParameter = curveParameter["securityParameter"]
	elif isinstance(curveParameter, str) and curveParameter.isalnum():
		curveName = curveParameter
	flag = True
	if isinstance(n, int):
		nString = n
	else:
		flag = False
	if isinstance(d, int):
		dString = d
	else:
		flag = False
	if isinstance(run, int) and run >= 1:
		runString = run
	if isVerbose is not False:
		print("Curve: ({0}, {1})".format(curveName, securityParameter))
		print("$n$:", nString)
		print("$d$:", dString)
		print("run:", runString)
	if flag and 2 <= d <= n:
		try:
			group = PairingGroup(curveName, secparam = securityParameter)
			pair(group.random(G1), group.random(G1))
			isSystemValid = True
			if isVerbose is not False:
				print("Is the system valid? Yes. ")
		except BaseException as e:
			if isVerbose is not False:
				print("Is the system valid? No. Failed to create the ``PairingGroup`` instance due to {0}. ".format(repr(e)))
				print()
	elif isVerbose is not False:
		print("Is the system valid? No. The parameters $n$ and $d$ should be two positive integers satisfying $2 \\leqslant d \\leqslant n$. ")
		print()
	
	# Execution #
	if isSystemValid:
		# Initialization #
		schemeFuzzyME = SchemeFuzzyME(group)
		sizeZR, sizeG1G2, sizeGT = schemeFuzzyME.getLengthOf(group.random(ZR)), schemeFuzzyME.getLengthOf(group.random(G1)), schemeFuzzyME.getLengthOf(group.random(GT))
		
		# Setup #
		startTime = perf_counter()
		mpk, msk = schemeFuzzyME.Setup(n = n, d = d)
		endTime = perf_counter()
		timeSetup = endTime - startTime
		sizeMpk, sizeMsk = schemeFuzzyME.getLengthOf(mpk), schemeFuzzyME.getLengthOf(msk)
		
		# EKGen #
		startTime = perf_counter()
		S_A = tuple(group.random(ZR) for _ in range(n))
		ek_S_A = schemeFuzzyME.EKGen(S_A)
		endTime = perf_counter()
		timeEKGen = endTime - startTime
		sizeEkSA = schemeFuzzyME.getLengthOf(ek_S_A)
		
		# DKGen #
		startTime = perf_counter()
		S_B = tuple(group.random(ZR) for _ in range(n))
		P_A = list(S_A)
		shuffle(P_A)
		P_A = P_A[:d] + list(group.random(ZR) for _ in range(n - d))
		shuffle(P_A)
		P_A = tuple(P_A)
		dk_SBPA = schemeFuzzyME.DKGen(S_B, P_A)
		endTime = perf_counter()
		timeDKGen = endTime - startTime
		sizeDkSBPA = schemeFuzzyME.getLengthOf(dk_SBPA)
		
		# Encryption #
		startTime = perf_counter()
		P_B = list(S_B)
		shuffle(P_B)
		P_B = P_B[:d] + list(group.random(ZR) for _ in range(n - d))
		shuffle(P_B)
		P_B = tuple(P_B)
		message = group.random(GT)
		CT = schemeFuzzyME.Encryption(ek_S_A, S_A, P_B, message)
		endTime = perf_counter()
		timeEncryption = endTime - startTime
		sizeCT = schemeFuzzyME.getLengthOf(CT)
		
		# Decryption #
		startTime = perf_counter()
		M = schemeFuzzyME.Decryption(dk_SBPA, S_A, P_A, S_B, P_B, CT)
		endTime = perf_counter()
		isSchemeCorrect = not isinstance(M, bool) and M == message
		timeDecryption = endTime - startTime
		
		# Destruction #
		del schemeFuzzyME
		if isVerbose is not False:
			print("Original:", message)
			print("Decrypted:", M)
			print("Is the scheme correct (M == message)? {0}. ".format("Yes" if isSchemeCorrect else "No"))
			print("Time:", (timeSetup, timeEKGen, timeDKGen, timeEncryption, timeDecryption))
			print("Space:", (sizeZR, sizeG1G2, sizeGT, sizeMpk, sizeMsk, sizeEkSA, sizeDkSBPA, sizeCT))
			print()
	
	# End #
	return [
		Parser.getSchemeName(), curveName, securityParameter, nString, dString, runString, 
		isSystemValid, isSchemeCorrect, 
		timeSetup, timeEKGen, timeDKGen, timeEncryption, timeDecryption, 
		sizeZR, sizeG1G2, sizeGT, 
		sizeMpk, sizeMsk, sizeEkSA, sizeDkSBPA, sizeCT
	]

def main() -> int:
	flag, encoding, outputFilePath, decimalPlace, isVerbose, runCount, waitingTime, overwritingConfirmed = Parser.parse(argv)
	if flag > EXIT_SUCCESS and flag > EOF:
		if any((PairingGroup is None, G1 is None, GT is None, ZR is None, pair is None, Element is None)):
			Parser.disableConsoleEchoes()
			print("The runtime environment of the Python Charm-Crypto framework is not correctly configured. ")
			print("Please refer to https://github.com/JHUISI/charm if necessary. ")
			errorLevel = EOF
		else:
			outputFilePath, overwritingConfirmed = Parser.checkOverwriting(outputFilePath, overwritingConfirmed)
			Parser.disableConsoleEchoes()
			print("The execution has started. ")
			print()
			
			# Parameters #
			curveParameters = (("SS512", 128), ("SS512", 160), ("SS512", 224), ("SS512", 256), ("SS512", 384), ("SS512", 512))
			queries = ("scheme", "curveName", "secparam", "n", "d", "runCount")
			validators = ("isSystemValid", "isSchemeCorrect")
			metrics = (
				"Setup (s)", "EKGen (s)", "DKGen (s)", "Encryption (s)", "Decryption (s)", 
				"elementOfZR (B)", "elementOfG1G2 (B)", "elementOfGT (B)", 
				"mpk (B)", "msk (B)", "ek_S_A (B)", "dk_SBPA (B)", "CT (B)"
			)
			getValidatorJudges = lambda x:x[queryLength:queryValidatorLength]
			getMetricJudges = lambda x:x[queryValidatorLength:]
			
			# Scheme #
			columns, queryLength, results = queries + validators + metrics, len(queries), []
			length, queryValidatorLength, runCountIndex = len(columns), queryLength + len(validators), queryLength - 1
			saver = Saver(outputFilePath, columns, decimalPlace = decimalPlace, encoding = encoding)
			try:
				for curveParameter in curveParameters:
					for n in range(10, 31, 5):
						for d in range(5, n, 5):
							averages = conductScheme(curveParameter, n = n, d = d, run = 1, isVerbose = isVerbose)
							for run in range(2, runCount + 1):
								result = conductScheme(curveParameter, n = n, d = d, run = run, isVerbose = isVerbose)
								for index in range(queryLength, queryValidatorLength):
									averages[index] += result[index]
								for index in range(queryValidatorLength, length):
									averages[index] = averages[index] + result[index] if isinstance(averages[index], (float, int)) and averages[index] > 0 and result[index] > 0 else "N/A"
							averages[runCountIndex] = runCount
							for index in range(queryValidatorLength, length):
								if isinstance(averages[index], (float, int)) and averages[index] > 0:
									averages[index] /= runCount
									if isinstance(averages[index], float) and averages[index].is_integer():
										averages[index] = int(averages[index])
								else:
									averages[index] = "N/A"
							results.append(averages)
							saver.save(results)
							if isVerbose:
								print()
				if not results:
					print("No experiments were conducted. ")
				elif not isVerbose:
					print()
			except KeyboardInterrupt:
				print()
				print("The experiments were interrupted by users. Saved results are retained. ")
			except BaseException as e:
				print()
				print("The experiments were interrupted by {0}. Saved results are retained. ".format(repr(e)))
			errorLevel = EXIT_SUCCESS if results and all(
				all(r == runCount for r in getValidatorJudges(result))
				and all(isinstance(r, (float, int)) and r > 0 for r in getMetricJudges(result))
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