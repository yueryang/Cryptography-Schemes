from os import chdir, makedirs, name, sep
from os.path import abspath, basename, dirname, exists, isfile, isdir, join, split, splitext
from sys import argv, exit
try:
	from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair, pc_element as Element
except:
	PairingGroup, G1, G2, GT, ZR, pair, Element = (None, ) * 7
from codecs import lookup
from getpass import getpass
from hashlib import md5, sha1, sha3_224, sha3_256, sha3_384, sha3_512
from math import ceil, log
from secrets import randbelow
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
	__SchemeName = "SchemeIBPME" # splitext(basename(__file__))[0]
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
		print("This is a possible implementation of the IBPME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ")
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

class SchemeIBPME:
	def __init__(self:object, group:None|PairingGroup = None) -> object: # This scheme is applicable to symmetric and asymmetric groups of prime orders. 
		self.__group = group if isinstance(group, PairingGroup) else PairingGroup("SS512", secparam = 512)
		if self.__group.secparam < 1:
			self.__group = PairingGroup(self.__group.groupType())
			print("Init: The securtiy parameter should be a positive integer, but it is not, which has been defaulted to {0}. ".format(self.__group.secparam))
		self.__operand = (1 << self.__group.secparam) - 1 # use to cast binary strings
		self.__mpk = None
		self.__msk = None
		self.__flag = False # to indicate whether it has already set up
	def __hash(self:object, *objs:tuple, bitLength:int|None = None) -> bytes:
		# bytes #
		bytesToBeHashed = b""
		for obj in objs:
			bytesToBeHashed += self.__group.serialize(obj) if isinstance(obj, Element) else bytes(obj)
		
		# length #
		length = bitLength if isinstance(bitLength, int) and bitLength >= 1 else self.__group.secparam
		
		# convert #
		if 512 == length:
			return sha3_512(bytesToBeHashed).digest()
		elif 384 == length:
			return sha3_384(bytesToBeHashed).digest()
		elif 256 == length:
			return sha3_256(bytesToBeHashed).digest()
		elif 224 == length:
			return sha3_224(bytesToBeHashed).digest()
		elif 160 == length:
			return sha1(bytesToBeHashed).digest()
		elif 128 == length:
			return md5(bytesToBeHashed).digest()
		else:
			return (int.from_bytes(sha3_512(bytesToBeHashed).digest() * ceil(length / 512), byteorder = "big") & ((1 << length) - 1)).to_bytes(ceil(length / 8))
	def Setup(self:object) -> tuple: # $\textbf{Setup}() \to (\textit{mpk}, \textit{msk})$
		# Checks #
		self.__flag = False
		
		# Scheme #
		q = self.__group.order() # $q \gets \|\mathbb{G}\|$
		g = self.__group.init(G1, 1) # $g \gets 1_{\mathbb{G}_1}$
		gHat = self.__group.init(G2, 1) # $\hat{g} \gets 1_{\mathbb{G}_2}$
		s, alpha, beta_0, beta_1 = self.__group.random(ZR), self.__group.random(ZR), self.__group.random(ZR), self.__group.random(ZR) # generate $s, \alpha, \beta_0, \beta_1 \in \mathbb{Z}_r$ randomly
		g1 = g ** alpha # $g_1 \gets g^\alpha$
		f = g ** beta_0 # $f \gets g^{\beta_0}$
		fHat = gHat ** beta_0 # $\hat{f} \gets \hat{g}^{\beta_0}$
		h = g ** beta_1 # $h \gets g^{\beta_1}$
		hHat = gHat ** beta_1 # $\hat{h} \gets \hat{g}^{\beta_1}$
		H = lambda x:self.__group.hash(self.__group.serialize(x), ZR) # $H: \mathbb{G}_T \to \mathbb{Z}_r$
		H1 = lambda x:self.__group.hash(x, G1) # $H_1: \{0, 1\}^* \to \mathbb{G}_1$
		H2 = lambda x:self.__group.hash(x, G2) # $H_2: \{0, 1\}^* \to \mathbb{G}_2$
		H3 = lambda x:self.__group.hash(self.__group.serialize(x), ZR) # $H_3: \mathbb{G}_T \to \mathbb{Z}_r$
		H4 = lambda x1, x2 = b"", x3 = b"":self.__hash(x1, x2, x3, self.__group.secparam) # $H_4: \{0, 1\}^\lambda \times \mathbb{G}_T^2 \times \mathbb{G}_1^2 \to \{0, 1\}^\lambda$
		if self.__group.secparam not in (128, 160, 224, 256, 384, 512):
			print("Setup: An irregular security parameter ($\\lambda = {0}$) is specified. It is recommended to use 224, 256, 384, 512, or 1024 as the security parameter. ".format(self.__group.secparam))
		H5 = lambda x1, x2 = b"", x3 = b"", x4 = b"", x5 = b"":self.__hash(x1, x2, x3, x4, x5, self.__group.secparam) # $H_5: \{0, 1\}^\lambda \times \mathbb{G}_T^2 \times \mathbb{G}_1^2 \to \{0, 1\}^\lambda$
		H6 = lambda x:self.__hash(x, self.__group.secparam * 3) # $H_6: \mathbb{G}_T \to \{0, 1\}^{3\lambda}$
		H7 = lambda x:self.__hash(x, self.__group.secparam << 1) # $H_7: \mathbb{G}_T \to \{0, 1\}^{2\lambda}$
		self.__mpk = (g, gHat, g1, f, h, fHat, hHat, H, H1, H2, H3, H4, H5, H6, H7) # $ \textit{mpk} \gets (g, \hat{g}, g_1, f, h, \hat{f}, \hat{h}, H, H_1, H_2, H_3, H_4, H_5, H_6, H_7)$
		self.__msk = (s, alpha) # $\textit{msk} \gets (s, \alpha)$
		
		# Flag #
		self.__flag = True
		return (self.__mpk, self.__msk) # \textbf{return} $(\textit{mpk}, \textit{msk})$
	def SKGen(self:object, snd:bytes) -> Element: # $\textbf{SKGen}(\sigma) \to \textit{ek}_\sigma$
		# Checks #
		if not self.__flag:
			print("SKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``SKGen`` subsequently. ")
			self.Setup()
		if isinstance(snd, bytes): # type check
			sigma = snd
		else:
			sigma = randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			print("SKGen: The variable $\\sigma$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		
		# Unpack #
		H1 = self.__mpk[8]
		s, alpha = self.__msk
		
		# Scheme #
		ek_sigma = H1(sigma) ** s # $\textit{ek}_\sigma \gets H_1(\sigma)^s$
		
		# Return #
		return ek_sigma # \textbf{return} $\textit{ek}_\sigma$
	def RKGen(self:object, rcv:bytes) -> tuple: # $\textbf{RKGen}(\rho) \to \textit{dk}_\rho$
		# Checks #
		if not self.__flag:
			print("RKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``RKGen`` subsequently. ")
			self.Setup()
		if isinstance(rcv, bytes): # type check
			rho = rcv
		else:
			rho = randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			print("RKGen: The variable $\\rho$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		
		# Unpack #
		H2 = self.__mpk[9]
		s, alpha = self.__msk
		
		# Scheme #
		d1 = H2(rho) ** s # $d_1 \gets H_2(\rho)^s$
		d2 = H2(rho) ** alpha # $d_2 \gets H_2(\rho)^\alpha$
		dk_rho = (d1, d2) # $\textit{dk}_\rho \gets (d_1, d_2)$
		
		# Return #
		return dk_rho # \textbf{return} $\textit{dk}_\rho$
	def PKGen(self:object, dkrho:Element, snd:bytes) -> tuple: # $\textbf{PKGen}(\textit{dk}_\rho, \sigma) \to \textit{pdk}_{\rho, \sigma}$
		# Checks #
		if not self.__flag:
			print("PKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``PKGen`` subsequently. ")
			self.Setup()
		if isinstance(dkrho, tuple) and len(dkrho) == 2 and all(isinstance(ele, Element) for ele in dkrho): # hybrid check
			dk_rho = dkrho
		else:
			dk_rho = self.RKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"))
			print("PKGen: The variable $\\textit{dk}_\\rho$ should be a tuple containing 2 elements, but it is not, which has been generated randomly. ")
		if isinstance(snd, bytes): # type check
			sigma = snd
		else:
			sigma = randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			print("PKGen: The variable $\\sigma$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		
		# Unpack #
		gHat, fHat, hHat, H, H1, H3 = self.__mpk[1], self.__mpk[5], self.__mpk[6], self.__mpk[7], self.__mpk[8], self.__mpk[10]
		d1, d2 = dk_rho
		
		# Scheme #
		y = self.__group.random(ZR) # generate $y \gets \mathbb{Z}_r$ randomly
		eta = pair(H1(sigma), d1) # $\eta \gets e(H_1(\sigma), d_1)$
		y1 = d2 ** H3(eta) * (fHat * hHat ** H(eta)) ** y # $y_1 \gets d_2^{H_3(\eta)}(\hat{f}\hat{h}^{H(\eta)})^y$
		y2 = gHat ** y # $y_2 \gets \hat{g}^y$
		pdk = (y1, y2) # $\textit{pdk}_{(\rho, \sigma)} \gets (y_1, y_2)$
		
		# Return #
		return pdk # \textbf{return} $\textit{pdk}_{(\rho, \sigma)}$
	def Enc(self:object, eksigma:Element, rcv:bytes, message:int|bytes) -> tuple: # $\textbf{Enc}(\textit{ek}_\sigma, \textit{id}_2, m) \to C$
		# Checks #
		if not self.__flag:
			print("Enc: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Enc`` subsequently. ")
			self.Setup()
		if isinstance(eksigma, Element) and eksigma.type == G1: # type check
			ek_sigma = eksigma
		else:
			ek_sigma = self.SKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"))
			print("Enc: The variable $\\textit{ek}_\\sigma$ should be an element of $\\mathbb{G}_1$, but it is not, which has been generated randomly. ")
		if isinstance(rcv, bytes): # type check
			rho = rcv
		else:
			rho = randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			print("Enc: The variable $\\rho$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(message, int) and message >= 0: # type check
			m = message & self.__operand
			if message != m:
				print("Enc: The passed message (int) is too long, which has been cast. ")
		elif isinstance(message, bytes):
			m = int.from_bytes(message, byteorder = "big") & self.__operand
			if len(message) << 3 > self.__group.secparam:
				print("Enc: The passed message (bytes) is too long, which has been cast. ")
		else:
			m = int.from_bytes(b"SchemeIBPME", byteorder = "big") & self.__operand
			print("Enc: The variable $m$ should be an integer or a ``bytes`` object, but it is not, which has been defaulted to b\"SchemeIBPME\". ")
		
		# Unpack #
		g, g1, f, h, H, H2, H3, H4, H5, H6 = self.__mpk[0], self.__mpk[2], self.__mpk[3], self.__mpk[4], self.__mpk[7], self.__mpk[9], self.__mpk[10], self.__mpk[11], self.__mpk[12], self.__mpk[13]
		
		# Scheme #
		r = self.__group.random(ZR) # generate $r \in \mathbb{Z}_r$ randomly
		eta = pair(ek_sigma, H2(rho)) # $\eta \gets e(\textit{ek}_\sigma, H_2(\rho))$
		K_R = pair(g1, H2(rho)) ** (r * H3(eta)) # $K_R \gets e(g_1, H_2(\rho))^{r \cdot H_3(\eta)}$
		C1 = g ** r # $C_1 \gets g^r$
		C2 = (f * h ** H(eta)) ** r # $C_2 \gets (fh^{H(\eta)})^r$
		K_C = H4(m.to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"), eta, K_R) # $K_C \gets H_4(m, \eta, K_R)$
		Y = H5(m.to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"), K_C, K_R, C1, C2) # $Y \gets H_5(m, K_C, K_R, C_1, C_2)$
		C3 = int.from_bytes(m.to_bytes(ceil(self.__group.secparam / 8), byteorder = "big") + K_C + Y, byteorder = "big") ^ int.from_bytes(H6(K_R), byteorder = "big") # $C_3 \gets (m || K_C || Y) \oplus H_6(K_R)$
		C = (C1, C2, C3) # $C \gets (C_1, C_2, C_3)$
		
		# Return #
		return C # \textbf{return} $C$
	def ProxyDec(self:object, _pdk:tuple, cipher:tuple) -> tuple|bool: # $\textbf{ProxyDec}(\textit{pdk}, C) \to \textit{CT}$
		# Checks #
		if not self.__flag:
			print("ProxyDec: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``ProxyDec`` subsequently. ")
			self.Setup()
		if isinstance(_pdk, tuple) and len(_pdk) == 2 and all(isinstance(ele, Element) for ele in _pdk): # hybrid check
			pdk = _pdk
		else:
			pdk = self.PKGen(
				self.RKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")), 
				randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			)
			print("ProxyDec: The variable $\\textit{pdk}$ should be a tuple containing 2 elements, but it is not, which has been generated randomly. ")
		if isinstance(cipher, tuple) and len(cipher) == 3 and all(isinstance(ele, Element) for ele in cipher[:2]) and isinstance(cipher[2], int): # hybrid check
			C = cipher
		else:
			C = self.Enc(
				self.SKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")), 
				randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"), b"SchemeIBPME"
			)
			print("ProxyDec: The variable $C$ should be a tuple containing 2 elements and an integer, but it is not, which has been generated randomly with $m$ set to b\"SchemeIBPME\". ")
		
		# Unpack #
		H5, H6, H7 = self.__mpk[12], self.__mpk[13], self.__mpk[14]
		y1, y2 = pdk
		C1, C2, C3 = C
		
		# Scheme #
		K_R = pair(C1, y1) / pair(C2, y2) # $K_R \gets e(C_1, y_1) / e(C_2, y_2)$
		m_KC_Y = C3 ^ int.from_bytes(H6(K_R), byteorder = "big") # $m || K_C || Y \gets C_3 \oplus H_6(K_R)$
		token = ceil(self.__group.secparam / 8)
		m_KC_Y = m_KC_Y.to_bytes(token * 3, byteorder = "big")
		m_KC, Y = m_KC_Y[:-token], m_KC_Y[-token:]
		if Y == H5(m_KC, K_R, C1, C2): # \textbf{if} $Y = H_5(m, K_C, K_R, C_1, C_2) $\textbf{then}
			CT1 = C1 # \quad$\textit{CT}_1 \gets C_1$
			CT2 = int.from_bytes(m_KC, byteorder = "big") ^ int.from_bytes(H7(K_R), byteorder = "big") # \quad$\textit{CT}_2 \gets (m || K_C) \oplus H_7(K_R)$
			CT = (CT1, CT2) # \quad$\textit{CT} \gets (\textit{CT}_1, \textit{CT}_2)$
		else: # \textbf{else}
			CT = False # \quad$\textit{CT} \gets \perp$
		# \textbf{end if}
		
		# Return #
		return CT # \textbf{return} $\textit{CT}$
	def Dec1(self:object, dkrho:tuple, snd:bytes, cipher:tuple) -> int|bool: # $\textbf{Dec}_1(\textit{dk}_\rho, \sigma, C) \to m$
		# Checks #
		if not self.__flag:
			print("Dec1: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Dec1`` subsequently. ")
			self.Setup()
		if isinstance(dkrho, tuple) and len(dkrho) == 2 and all(isinstance(ele, Element) for ele in dkrho): # hybrid check
			dk_rho = dkrho
		else:
			dk_rho = self.RKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"))
			print("Dec1: The variable $\\textit{dk}_\\rho$ should be a tuple containing 2 elements, but it is not, which has been generated randomly. ")
		if isinstance(snd, bytes): # type check
			sigma = snd
		else:
			sigma = randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			print("Dec1: The variable $\\sigma$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(cipher, tuple) and len(cipher) == 3 and all(isinstance(ele, Element) for ele in cipher[:2]) and isinstance(cipher[2], int): # hybrid check
			C = cipher
		else:
			C = self.Enc(
				self.SKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")), 
				randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"), b"SchemeIBPME"
			)
			print("Dec1: The variable $C$ should be a tuple containing 2 elements and an integer, but it is not, which has been generated randomly with $m$ set to b\"SchemeIBPME\". ")
		
		# Unpack #
		H1, H3, H4, H5, H6 = self.__mpk[8], self.__mpk[10], self.__mpk[11], self.__mpk[12], self.__mpk[13]
		d1, d2 = dk_rho
		C1, C2, C3 = C
		
		# Scheme #
		eta = pair(H1(sigma), d1) # $\eta \gets e(H_1(\sigma), d_1)$
		K_R = pair(C1, d2 ** H3(eta)) # $K_R \gets e(C_1, d_2^{H_3(\eta)})$
		m_KC_Y = C3 ^ int.from_bytes(H6(K_R), byteorder = "big") # $m || K_C || Y \gets C_3 \oplus H_6(K_R)$
		token = ceil(self.__group.secparam / 8)
		m_KC_Y = m_KC_Y.to_bytes(token * 3, byteorder = "big")
		m, K_C, Y = m_KC_Y[:token], m_KC_Y[token:-token], m_KC_Y[-token:]
		if K_C != H4(m, eta, K_R) or Y != H5(m, K_C, K_R, C1, C2): # \textbf{if} $K_C \neq H_4(m, \eta, K_R) \lor Y \neq H_5(m, K_C, K_R, C_1, C_2) $\textbf{then}
			m = False # \quad$m \gets \perp$
		else:
			m = int.from_bytes(m, byteorder = "big")
		# \textbf{end if}
		
		# Return #
		return m # \textbf{return} $m$
	def Dec2(self:object, dkrho:tuple, snd:bytes, cipherText:tuple) -> int|bool: # $\textbf{Dec}_2(\textit{dk}_\rho, \sigma, \textit{CT}) \to m'$
		# Checks #
		if not self.__flag:
			print("Dec2: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Dec2`` subsequently. ")
			self.Setup()
		if isinstance(dkrho, tuple) and len(dkrho) == 2 and all(isinstance(ele, Element) for ele in dkrho): # hybrid check
			dk_rho = dkrho
		else:
			dk_rho = self.RKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"))
			print("Dec2: The variable $\\textit{dk}_\\rho$ should be a tuple containing 2 elements, but it is not, which has been generated randomly. ")
		if isinstance(snd, bytes): # type check
			sigma = snd
		else:
			sigma = randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
			print("Dec2: The variable $\\sigma$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(cipherText, tuple) and len(cipherText) == 2 and isinstance(cipherText[0], Element) and isinstance(cipherText[1], int): # hybrid check
			CT = cipherText
		elif isinstance(cipherText, bool):
			return False
		else:
			CT = self.ProxyDec(
				self.PKGen(
					self.RKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")), 
					randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")
				), self.Enc(
					self.SKGen(randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big")), 
					randbelow(1 << self.__group.secparam).to_bytes(ceil(self.__group.secparam / 8), byteorder = "big"), b"SchemeIBPME"
				)
			)
			print("Dec2: The variable $\\textit{CT}$ should be a tuple containing an element and an integer, but it is not, which has been generated randomly with $m$ set to b\"SchemeIBPME\". ")
		
		# Unpack #
		H1, H3, H4, H7 = self.__mpk[8], self.__mpk[10], self.__mpk[11], self.__mpk[14]
		d1, d2 = dk_rho
		CT1, CT2 = CT
		
		# Scheme #
		eta = pair(H1(sigma), d1) # $\eta \gets e(H_1(\sigma), d_1)$
		K_R = pair(CT1, d2 ** H3(eta)) # $K_R \gets e(C_1, d_2^{H_3(\eta)})$
		m_KC = CT2 ^ int.from_bytes(H7(K_R), byteorder = "big") # $m || K_C \gets \textit{CT}_2 \oplus H_7(K_R)$
		token = ceil(self.__group.secparam / 8)
		m_KC = m_KC.to_bytes(token << 1, byteorder = "big")
		m, K_C = m_KC[:-token], m_KC[-token:]
		if K_C != H4(m, eta, K_R): # \textbf{if} $K_C \neq H_4(m, \eta, K_R) $\textbf{then}
			m = False # \quad$m \gets \perp$
		else:
			m = int.from_bytes(m, byteorder = "big")
		# \textbf{end if}
		
		# Return #
		return m # \textbf{return} $m$
	def getLengthOf(self:object, obj:Element|tuple|list|set|bytes|int) -> int:
		if isinstance(obj, Element):
			return len(self.__group.serialize(obj))
		elif isinstance(obj, bytes):
			return len(obj)
		elif isinstance(obj, (tuple, list, set)):
			sizes = tuple(self.getLengthOf(o) for o in obj)
			return sum(sizes) if all(isinstance(size, int) and size >= 1 for size in sizes) else "N/A"
		elif isinstance(obj, dict):
			sizes = tuple(self.getLengthOf(value) for value in obj.values())
			return sum(sizes) if all(isinstance(size, int) and size >= 1 for size in sizes) else "N/A"
		elif isinstance(obj, int):
			return ceil(ceil(log(obj + 1, 256)) / (self.__group.secparam >> 3)) * (self.__group.secparam >> 3)
		elif callable(obj):
			if self.__mpk and obj == self.__mpk[13]: # H6
				return (self.__group.secparam >> 3) * 3
			elif self.__mpk and obj == self.__mpk[14]: # H7
				return self.__group.secparam >> 2
			else:
				return self.__group.secparam >> 3
		else:
			return "N/A"


def conductScheme(curveParameter:tuple|list|dict|str, run:int|None = None, isVerbose:bool = True) -> list:
	# Begin #
	curveName, securityParameter, runString = "N/A", 512, "N/A" # the default value of the security parameter in the Python Charm-Crypto framework is 512
	isSystemValid, isProxyDecPassed, isDec1Passed, isDec2Passed = False, False, False, False
	timeSetup, timeSKGen, timeRKGen, timePKGen, timeEnc, timeProxyDec, timeDec1, timeDec2 = ("N/A", ) * 8
	sizeZR, sizeG1, sizeG2, sizeGT = ("N/A", ) * 4
	sizeMpk, sizeMsk, sizeSKGen, sizeDkRho, sizePdk, sizeC, sizeCT = ("N/A", ) * 7
	
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
	if isinstance(run, int) and run >= 1:
		runString = run
	if isVerbose is not False:
		print("Curve: ({0}, {1})".format(curveName, securityParameter))
		print("run:", runString)
	if flag:
		try:
			group = PairingGroup(curveName, secparam = securityParameter)
			isSystemValid = True
			if isVerbose is not False:
				print("Is the system valid? Yes. ")
		except BaseException as e:
			if isVerbose is not False:
				print("Is the system valid? No. Failed to create the ``PairingGroup`` instance due to {0}. ".format(repr(e)))
				print()
	
	# Execution #
	if isSystemValid:
		# Initialization #
		schemeIBPME = SchemeIBPME(group)
		sizeZR, sizeG1, sizeG2, sizeGT = (
			schemeIBPME.getLengthOf(group.random(ZR)), schemeIBPME.getLengthOf(group.random(G1)), 
			schemeIBPME.getLengthOf(group.random(G2)), schemeIBPME.getLengthOf(group.random(GT))
		)
		
		# Setup #
		startTime = perf_counter()
		mpk, msk = schemeIBPME.Setup()
		endTime = perf_counter()
		timeSetup = endTime - startTime
		sizeMpk, sizeMsk = schemeIBPME.getLengthOf(mpk), schemeIBPME.getLengthOf(msk)
		
		# SKGen #
		startTime = perf_counter()
		sigma = randbelow(1 << group.secparam).to_bytes(ceil(group.secparam / 8), byteorder = "big")
		ek_sigma = schemeIBPME.SKGen(sigma)
		endTime = perf_counter()
		timeSKGen = endTime - startTime
		sizeSKGen = schemeIBPME.getLengthOf(ek_sigma)
		
		# RKGen #
		startTime = perf_counter()
		rho = randbelow(1 << group.secparam).to_bytes(ceil(group.secparam / 8), byteorder = "big")
		dk_rho = schemeIBPME.RKGen(rho)
		endTime = perf_counter()
		timeRKGen = endTime - startTime
		sizeDkRho = schemeIBPME.getLengthOf(dk_rho)
		
		# PKGen #
		startTime = perf_counter()
		pdk = schemeIBPME.PKGen(dk_rho, sigma)
		endTime = perf_counter()
		timePKGen = endTime - startTime
		sizePdk = schemeIBPME.getLengthOf(pdk)
		
		# Enc #
		startTime = perf_counter()
		message = int.from_bytes(b"SchemeIBPME", byteorder = "big")
		C = schemeIBPME.Enc(ek_sigma, rho, message)
		endTime = perf_counter()
		timeEnc = endTime - startTime
		sizeC = schemeIBPME.getLengthOf(C)
			
		# ProxyDec #
		startTime = perf_counter()
		CT = schemeIBPME.ProxyDec(pdk, C)
		endTime = perf_counter()
		timeProxyDec = endTime - startTime
		isProxyDecPassed = not isinstance(CT, bool)
		sizeCT = schemeIBPME.getLengthOf(CT)
		
		# Dec1 #
		startTime = perf_counter()
		m = schemeIBPME.Dec1(dk_rho, sigma, C)
		endTime = perf_counter()
		timeDec1 = endTime - startTime
		isDec1Passed = not isinstance(m, bool) and m == message
		
		# Dec2 #
		startTime = perf_counter()
		mPrime = schemeIBPME.Dec2(dk_rho, sigma, CT)
		endTime = perf_counter()
		timeDec2 = endTime - startTime
		isDec2Passed = not isinstance(mPrime, bool) and mPrime == message
		
		# Destruction #
		del schemeIBPME
		if isVerbose is not False:
			print("Original:", message)
			print("Dec1:", m)
			print("Dec2:", mPrime)
			print("Is ``ProxyDec`` passed? {0}. ".format("Yes" if isProxyDecPassed else "No"))
			print("Is ``Dec1`` passed (m == message)? {0}. ".format("Yes" if isDec1Passed else "No"))
			print("Is ``Dec2`` passed (m' == message)? {0}. ".format("Yes" if isDec2Passed else "No"))
			print("Time:", (timeSetup, timeSKGen, timeRKGen, timePKGen, timeEnc, timeProxyDec, timeDec1, timeDec2))
			print("Space:", (sizeZR, sizeG1, sizeG2, sizeGT, sizeMpk, sizeMsk, sizeSKGen, sizeDkRho, sizePdk, sizeC, sizeCT))
			print()
	
	# End #
	return [
		Parser.getSchemeName(), curveName, securityParameter, runString, 
		isSystemValid, isProxyDecPassed, isDec1Passed, isDec2Passed, 
		timeSetup, timeSKGen, timeRKGen, timePKGen, timeEnc, timeProxyDec, timeDec1, timeDec2, 
		sizeZR, sizeG1, sizeG2, sizeGT, 
		sizeMpk, sizeMsk, sizeSKGen, sizeDkRho, sizePdk, sizeC, sizeCT
	]

def main() -> int:
	flag, encoding, outputFilePath, decimalPlace, isVerbose, runCount, waitingTime, overwritingConfirmed = Parser.parse(argv)
	if flag > EXIT_SUCCESS and flag > EOF:
		if any((PairingGroup is None, G1 is None, G2 is None, GT is None, ZR is None, pair is None, Element is None)):
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
			curveParameters = ("MNT201", "MNT224", "BN254", ("SS512", 128), ("SS512", 256), ("SS512", 512), ("SS1024", 512), ("SS1024", 1024))
			queries = ("scheme", "curveName", "secparam", "runCount")
			validators = ("isSystemValid", "isProxyDecPassed", "isDec1Passed", "isDec2Passed")
			metrics = (
				"Setup (s)", "SKGen (s)", "RKGen (s)", "PKGen (s)", "Enc (s)", "ProxyDec (s)", "Dec1 (s)", "Dec2 (s)", 
				"elementOfZR (B)", "elementOfG1 (B)", "elementOfG2 (B)", "elementOfGT (B)", 
				"mpk (B)", "msk (B)", "ek_sigma (B)", "dk_rho (B)", "pdk (B)", "C (B)", "CT (B)"
			)
			getValidatorJudges = lambda x:x[queryLength:queryValidatorLength]
			getMetricJudges = lambda x:x[queryValidatorLength:]
			
			# Scheme #
			columns, queryLength, results = queries + validators + metrics, len(queries), []
			length, queryValidatorLength, runCountIndex = len(columns), queryLength + len(validators), queryLength - 1
			saver = Saver(outputFilePath, columns, decimalPlace = decimalPlace, encoding = encoding)
			try:
				for curveParameter in curveParameters:
					averages = conductScheme(curveParameter, run = 1, isVerbose = isVerbose)
					for run in range(2, runCount + 1):
						result = conductScheme(curveParameter, run = run, isVerbose = isVerbose)
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