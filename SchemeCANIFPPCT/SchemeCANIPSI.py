from os import chdir, makedirs, name, sep
from os.path import abspath, basename, dirname, exists, isfile, isdir, join, split, splitext
from sys import argv, exit
try:
	from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair, pc_element as Element
except:
	PairingGroup, G1, G2, GT, ZR, pair, Element = (None, ) * 7
from codecs import lookup
from getpass import getpass
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
	__SchemeName = "SchemeCANIPSI" # splitext(basename(__file__))[0]
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
		print("This is a possible implementation of the CA-NI-PSI cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ")
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

class SchemeCANIPSI:
	__DefaultN, __DefaultM = 30, 10
	def __init__(self:object, group:None|PairingGroup = None) -> object: # This scheme is applicable to symmetric and asymmetric groups of prime orders.
		self.__group = group if isinstance(group, PairingGroup) else PairingGroup("SS512", secparam = 512)
		if self.__group.secparam < 1:
			self.__group = PairingGroup(self.__group.groupType())
			print("Init: The securtiy parameter should be a positive integer, but it is not, which has been defaulted to {0}. ".format(self.__group.secparam))
		self.__n = SchemeCANIPSI.__DefaultN
		self.__m = SchemeCANIPSI.__DefaultM
		self.__bpk = None
		self.__bsk = None
		self.__bFlag = False # to indicate whether it has already set up
		self.__mpk = None
		self.__msk = None
		self.__flag = False # to indicate whether it has already set up
	def __computeCoefficients(self:object, roots:tuple|list, k:Element|int|float|None = None) -> tuple:
		flag = False
		if isinstance(roots, (tuple, list)) and roots:
			n = len(roots)
			if isinstance(roots[0], Element) and all(isinstance(root, Element) and root.type == roots[0].type for root in roots):
				flag, coefficients = True, [None] * (n - 1) + [roots[0], self.__group.init(roots[0].type, 1)]
				offset = k if isinstance(k, Element) and k.type == roots[0].type else None
			elif isinstance(roots[0], (int, float)) and all(isinstance(root, (int, float)) for root in roots):
				flag, coefficients = True, [None] * (n - 1) + [roots[0], 1]
				offset = k if isinstance(k, (int, float)) else None
		if flag:
			cnt = n - 2
			for r in roots[1:]:
				coefficients[cnt] = r * coefficients[cnt + 1]
				for i in range(cnt + 1, n - 1):
					coefficients[i] += r * coefficients[i + 1]
				coefficients[n - 1] += r
				cnt -= 1
			for i in range(n - 1, -1, -2):
				coefficients[i] = -coefficients[i]
			if offset is not None:
				coefficients[0] += offset
			return tuple(coefficients)
		else:
			return (k, )
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
	def __generateRandomNonZeroZRElement(self:object) -> Element:
		element = self.__group.random(ZR)
		while element == self.__group.init(ZR, 0):
			element = self.__group.random(ZR)
		return element
	def BSetup(self:object, n:int = __DefaultN, m:int = __DefaultM) -> tuple: # $\textbf{BSetup}(n, m) \to (\textit{bpk}, \textit{bsk})$
		# Checks #
		self.__bFlag = False
		if isinstance(n, int) and isinstance(m, int) and 1 <= m <= n: # boundary check
			self.__n, self.__m = n, m
		else:
			self.__n, self.__m = SchemeCANIPSI.__DefaultN, SchemeCANIPSI.__DefaultM
			print(
				"BSetup: The variables $n$ and $m$ should be two positive integers satisfying $1 \\leqslant m \\leqslant n$, but they are not, "
				+ "which have been defaulted to ${0}$ and ${1}$, respectively. ".format(SchemeCANIPSI.__DefaultN, SchemeCANIPSI.__DefaultM)
			)
		
		# Scheme #
		g = self.__group.random(G1) # generate $g \in \mathbb{G}_1$ randomly
		g1 = self.__group.random(G1) # generate $g_1 \in \mathbb{G}_1$ randomly
		H1 = lambda x: self.__group.hash(x, G1) # $H_1: \{0, 1\}^* \to \mathbb{G}_1$
		H2 = lambda x: self.__group.hash(self.__group.serialize(x), ZR) # $H_2: \mathbb{G}_1 \to \mathbb{Z}_r$
		omega = self.__group.random(ZR) # generate $\omega \in \mathbb{Z}_r$ randomly
		t1, t2, t3, t4 = tuple(self.__generateRandomNonZeroZRElement() for _ in range(4)) # generate $t_1, t_2, t_3, t_4 \in \mathbb{Z}_r^*$ randomly
		Omega = pair(g, g) ** (t1 * t2 * omega) # $\Omega \gets e(g, g)^{t_1 t_2 \omega}$
		v1 = g ** t1 # $v_1 \gets g^{t_1}$
		v2 = g ** t2 # $v_2 \gets g^{t_2}$
		v3 = g ** t3 # $v_3 \gets g^{t_3}$
		v4 = g ** t4 # $v_4 \gets g^{t_4}$
		self.__bpk = (g, g1, H1, H2, Omega, v1, v2, v3, v4) # $\textit{bpk} \gets (g, g_1, H_1, H_2, \Omega, v_1, v_2, v_3, v_4)$
		self.__bsk = (omega, t1, t2, t3, t4) # $\textit{bsk} \gets (\omega, t_1, t_2, t_3, t_4)$
		
		# Return #
		self.__bFlag = True
		return (self.__bpk, self.__bsk) # \textbf{return} $(\textit{bpk}, \textit{bsk})$
	def BKGen(self:object, ID_i:object) -> tuple: # $\textbf{BKGen}(\textit{ID}_i) \to \textit{bsk}_{\textit{ID}_i}$
		# Checks #
		if not self.__bFlag:
			print("BKGen: The ``BSetup`` procedure has not been called yet. The program will call the ``BSetup`` first and finish the ``BKGen`` subsequently. ")
			self.BSetup()
		
		# Unpack #
		pass
		
		# Scheme #
		k_i = self.__group.random(ZR) # generate $k_i \in \mathbb{Z}_r$ randomly
		bsk_ID_i = k_i # $\textit{bsk}_{\textit{ID}_i} \gets k_i$

		# Return #
		return bsk_ID_i # \textbf{return} $\textit{bsk}_{\textit{ID}_i}$
	def BEncryption(self:object, TPi:bytes, _s:tuple|list, si:Element) -> tuple: # $\textbf{BEncryption}(\textit{TP}_i) \to \textit{BCT}_{\textit{TP}_i}$
		# Checks #
		if not self.__bFlag:
			print("BEncryption: The ``BSetup`` procedure has not been called yet. The program will call the ``BSetup`` first and finish the ``BEncryption`` subsequently. ")
			self.BSetup()
		if isinstance(TPi, bytes): # type check
			TP_i = TPi
		else:
			TP_i = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("BEncryption: The variable $\\textit{TP}_i$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(_s, (tuple, list)) and len(_s) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in _s): # hybrid check
			s = _s
			if si in s:
				s_i = si
			else:
				s_i = s[randbelow(self.__n)]
				print("BEncryption: The variable $s_i$ should be an element in $s$, but it is not, which has been generated randomly. ")
		else:
			s = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("BEncryption: The variable $s$ should be a tuple or a list containing $n$ elements of \\mathbb{Z}_r, but it is not, which has been generated randomly. ")
			s_i = s[randbelow(self.__n)]
			print("BEncryption: The variable $s_i$ has been generated accordingly. ")
		
		# Unpack #
		g1, H1, H2, Omega, v1, v2, v3, v4 = self.__bpk[1:]
		
		# Scheme #
		s1_i, s2_i = self.__group.random(ZR), self.__group.random(ZR) # generate $s_{1_i}, s_{2_i} \in \mathbb{Z}_r$ randomly
		VVec = tuple(H2(Omega ** s[i]) for i in range(self.__n)) # $V_i \gets H_2(\Omega^{s_i}), \forall i \in \{1, 2, \cdots, n\}$
		C0_i = (g1 * H1(TP_i)) ** s_i # $C_{0_i} \gets (g_1 H_1(t_i || p_i))^{s_i}$
		C1_i = v1 ** (s_i - s1_i) # $C_{1_i} \gets v_1^{s_i - s_{1_i}}$
		C2_i = v2 ** s1_i # $C_{2_i} \gets v_2^{s_{1_i}}$
		C3_i = v3 ** (s_i - s2_i) # $C_{3_i} \gets v_2^{s_i - s_{2_i}}$
		C4_i = v4 ** s2_i # $C_{4_i} \gets v_2^{s_{1_i}}$
		aVec = self.__computeCoefficients(VVec) # compute $a_0, a_1, a_2, \cdots, a_n$ s.t. $\forall x \in \mathbb{Z}_r$, we have $f(x) = \prod\limits_{i = 1}^n (x - V_i) = a_0 + \sum\limits_{i = 1}^n a_i x^i$
		BCT_TP_i = ((C0_i, C1_i, C2_i, C3_i, C4_i), aVec) # $\textit{BCT}_{\textit{TPs}} \gets ((C_{0_i}, C_{1_i}, C_{2_i}, C_{3_i}, C_{4_i}), \vec{a})$
		
		# Return #
		return BCT_TP_i # \textbf{return} $\textit{BCT}_{\textit{TP}_i}$
	def BTokenGen(self:object, QTPi:tuple, bskIDi:Element) -> tuple: # $\textbf{BTokenGen}(\textit{QTP}_i, \textit{bsk}_{\textit{ID}_i}) \to \textit{btoken}_i$
		# Checks #
		if not self.__bFlag:
			print("BTokenGen: The ``BSetup`` procedure has not been called yet. The program will call the ``BSetup`` first and finish the ``BTokenGen`` subsequently. ")
			self.BSetup()
		if isinstance(QTPi, bytes): # type check
			QTP_i = QTPi
		else:
			QTP_i = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("BTokenGen: The variable $\\textit{QTP}_i$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(bskIDi, Element) and bskIDi.type == ZR: # type check
			bsk_ID_i = bskIDi
		else:
			bsk_ID_i = self.BKGen(self.__group.random(ZR))
			print("BTokenGen: The variable $\\textit{bsk}_{\\textit{ID}_i}$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		g, g1, H1, v1, v2 = self.__bpk[0], self.__bpk[1], self.__bpk[2], self.__bpk[5], self.__bpk[6]
		omega, t1, t2, t3, t4 = self.__bsk
		
		# Scheme #
		r1_i , r2_i = self.__group.random(ZR), self.__group.random(ZR) # generate $r_{1_i}, r_{2_i} \in \mathbb{Z}_r$ randomly
		T0_i = g ** (r1_i * t1 * t2 + r2_i * t3 * t4) # $T_{0_i} \gets g^{r_{1_i} t_1 t_2 + r_{2_i} t_3 t_4}$
		T1_i = v2 ** omega * ((g1 * H1(QTP_i)) ** (-r1_i * t2)) # $T_{1_i} \gets v_2^\omega (g_1 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{1_i} t_2}$
		T2_i = v1 ** omega * ((g1 * H1(QTP_i)) ** (-r1_i * t1)) # $T_{2_i} \gets v_1^\omega (g_1 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{1_i} t_1}$
		T3_i = (g1 * H1(QTP_i)) ** (-r2_i * t4) # $T_{3_i} \gets (g_1 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{2_i} t_4}$
		T4_i = (g1 * H1(QTP_i)) ** (-r2_i * t3) # $T_{4_i} \gets (g_1 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{2_i} t_3}$
		btoken_i = (T0_i, T1_i, T2_i, T3_i, T4_i) # $\textit{btoken} \gets (T_{0_i}, T_{1_i}, T_{2_i}, T_{3_i}, T_{4_i})$
		
		# Return #
		return btoken_i # \textbf{return} $\textit{btoken}_i$
	def BQuery(self:object, BCTTPi:tuple, btokeni:tuple) -> bool: # $\textbf{BQuery}(\textit{BCT}_{\textit{TP}_i}, \textit{btoken}_i) \to y, y \in \{0, 1\}$
		# Checks #
		if not self.__bFlag:
			print("BQuery: The ``BSetup`` procedure has not been called yet. The program will call the ``BSetup`` first and finish the ``BQuery`` subsequently. ")
			self.BSetup()
		if not (isinstance(BCTTPi, tuple) and len(BCTTPi) == 2 and all(isinstance(ele, tuple) for ele in BCTTPi)
			and len(BCTTPi[0]) == 5 and len(BCTTPi[1]) >= 1 and all(isinstance(ele, Element) for vector in BCTTPi for ele in vector)):
			return False
		if not (isinstance(btokeni, tuple) and len(btokeni) == 5 and all(isinstance(ele, Element) for ele in btokeni)):
			return False
		
		# Unpack #
		H2 = self.__bpk[3]
		CVec_i, aVec = BCTTPi
		C0_i, C1_i, C2_i, C3_i, C4_i = CVec_i
		T0_i, T1_i, T2_i, T3_i, T4_i = btokeni
		
		# Scheme #
		try:
			VPrime_i = H2(pair(T0_i, C0_i) * pair(T1_i, C1_i) * pair(T2_i, C2_i) * pair(T3_i, C3_i) * pair(T4_i, C4_i))
			return self.__computePolynomial(VPrime_i, aVec) == self.__group.init(ZR, 0)
		except Exception:
			return False
	def Setup(self:object, n:int = __DefaultN, m:int = __DefaultM) -> tuple: # $\textbf{Setup}(n, m) \to (\textit{mpk}, \textit{msk})$
		# Checks #
		self.__flag = False
		if isinstance(n, int) and isinstance(m, int) and 1 <= m <= n:
			self.__n, self.__m = n, m
		else:
			self.__n, self.__m = SchemeCANIPSI.__DefaultN, SchemeCANIPSI.__DefaultM
			print(
				"Setup: The variables $n$ and $m$ should be two positive integers satisfying $1 \\leqslant m \\leqslant n$, but they are not, "
				+ "which have been defaulted to ${0}$ and ${1}$, respectively. ".format(SchemeCANIPSI.__DefaultN, SchemeCANIPSI.__DefaultM)
			)
		
		# Scheme #
		g1 = self.__group.random(G1) # generate $g_1 \in \mathbb{G}_1$ randomly
		g2 = self.__group.random(G2) # generate $g_2 \in \mathbb{G}_2$ randomly
		g3 = self.__group.random(G1) # generate $g_3 \in \mathbb{G}_1$
		H1 = lambda x: self.__group.hash(x, G1) # $H_1: \{0, 1\}^* \to \mathbb{G}_1$
		H2 = lambda x: self.__group.hash(self.__group.serialize(x), ZR) # $H_2: \mathbb{G}_T \to \mathbb{Z}_r$
		H3 = lambda x: self.__group.hash(x, ZR) # $H_3: \{0, 1\}^* \to \mathbb{Z}_r$
		H4 = lambda x: self.__group.hash(self.__group.serialize(x), ZR) # $H_4: \mathbb{G}_1 \to \mathbb{Z}_r$
		r, t, omega = self.__group.random(ZR, 3) # generate $r, t, \omega \in \mathbb{Z}_r$ randomly
		s, t1, t2, t3, t4 = tuple(self.__generateRandomNonZeroZRElement() for _ in range(5)) # generate $s, t_1, t_2, t_3, t_4 \in \mathbb{Z}_r^*$ randomly
		R = g1 ** r # $R \gets g_1^r$
		S = g2 ** s # $S \gets g_2^s$
		T = g1 ** t # $T \gets g_1^t$
		Omega = pair(g1, g2) ** (t1 * t2 * omega) # $\Omega \gets e(g_1, g_2)^{t_1 t_2 \omega}$
		v1 = g2 ** t1 # $v_1 \gets g_2^{t_1}$
		v2 = g2 ** t2 # $v_2 \gets g_2^{t_2}$
		v3 = g2 ** t3 # $v_3 \gets g_2^{t_3}$
		v4 = g2 ** t4 # $v_4 \gets g_2^{t_4}$
		self.__mpk = (g1, g2, g3, H1, H2, H3, H4, R, S, T, Omega, v1, v2, v3, v4) # $\textit{mpk} \gets (g_1, g_2, g_3, H_1, H_2, H_3, H_4, R, S, T, \Omega, v_1, v_2, v_3, v_4)$
		self.__msk = (r, s, t, omega, t1, t2, t3, t4) # $\textit{msk} \gets (r, s, t, \omega, t_1, t_2, t_3, t_4)$
		
		# Return #
		self.__flag = True
		return (self.__mpk, self.__msk) # \textbf{return} $(\textit{mpk}, \textit{msk})$
	def KGen(self:object, ID_i:object, _L:list = []) -> tuple: # $\textbf{KGen}(\textit{ID}_i, L) \to (\textit{sk}_{\textit{ID}_i}, \textit{ek}_{\textit{ID}_i})$
		# Checks #
		if not self.__flag:
			print("KGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``KGen`` subsequently. ")
			self.Setup()
		if isinstance(_L, list): # type check
			L = _L
		else:
			L = []
			print("KGen: The variable $L$ should be a list, but it is not, which has been initialized as an empty list. ")
		
		# Unpack #
		g1, H4 = self.__mpk[0], self.__mpk[6]
		r, s = self.__msk[0], self.__msk[1]
		
		# Scheme #
		k_i, x_i = self.__group.random(ZR), self.__generateRandomNonZeroZRElement() # generate $k_i \in \mathbb{Z}_r$ and $x_i \in \mathbb{Z}_r^*$
		z_i = (r - x_i) * (s * x_i) ** (-1) # $z_i \gets \frac{r - x_i}{s x_i}$
		Z_i = g1 ** z_i # $Z_i \gets g_1^{z_i}$
		sk_ID_i = k_i # $\textit{sk}_{\textit{ID}_i} \gets k_i$
		ek_ID_i = (x_i, Z_i) # $\textit{ek}_{\textit{ID}_i} \gets (x_i, Z_i)$
		tag_i = H4(Z_i ** x_i) # $\textit{tag}_i \gets H_4(Z_i^{x_i})$
		L.append((ID_i, k_i, tag_i)) # $L \gets L || ((\textit{ID}_i, k_i, \textit{tag}_i))$
		
		# Return #
		return (sk_ID_i, ek_ID_i) # \textbf{return} $(\textit{sk}_{\textit{ID}_i}, \textit{ek}_{\textit{ID}_i})$
	def Encryption(self:object, TPi:bytes, skIDi:Element, ekIDi:tuple, _s:tuple|list, si:Element) -> tuple: # $\textbf{Encryption}(\textit{TP}_i, \textit{sk}_{\textit{ID}_i}, \textit{ek}_{\textit{ID}_i}, s, s_i) \to \textit{CT}_{\textit{TP}_i}$
		# Checks #
		if not self.__flag:
			print("Encryption: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Encryption`` subsequently. ")
			self.Setup()
		if isinstance(TPi, bytes): # type check
			TP_i = TPi
		else:
			TP_i = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("Encryption: The variable $\\textit{TP}_i$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(skIDi, Element) and skIDi.type == ZR: # type check
			sk_ID_i = skIDi
		else:
			sk_ID_i = self.KGen(self.__group.random(ZR), [])[0]
			print("Encryption: The variable $\\textit{sk}_{\\textit{ID}_i}$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		if isinstance(ekIDi, tuple) and len(ekIDi) == 2 and all(isinstance(ele, Element) for ele in ekIDi): # hybrid check
			ek_ID_i = ekIDi
		else:
			ek_ID_i = self.KGen(self.__group.random(ZR), [])[1]
			print("Encryption: The variable $\\textit{ek}_{\\textit{ID}_i}$ should be a tuple containing 2 elements, but it is not, which has been generated randomly. ")
		if isinstance(_s, (tuple, list)) and len(_s) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in _s): # hybrid check
			s = _s
			if si in s:
				s_i = si
			else:
				s_i = s[randbelow(self.__n)]
				print("Encryption: The variable $s_i$ should be an element in $s$, but it is not, which has been generated randomly. ")
		else:
			s = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("Encryption: The variable $s$ should be a tuple or a list containing $n$ elements of \\mathbb{Z}_r, but it is not, which has been generated randomly. ")
			s_i = s[randbelow(self.__n)]
			print("Encryption: The variable $s_i$ has been generated accordingly. ")
		
		# Unpack #
		g1, g3, H1, H2, H3, S, T, Omega, v1, v2, v3, v4 = (
			self.__mpk[0], self.__mpk[2], self.__mpk[3], self.__mpk[4], self.__mpk[5], self.__mpk[8], 
			self.__mpk[9], self.__mpk[10], self.__mpk[11], self.__mpk[12], self.__mpk[13], self.__mpk[14]
		)
		x_i, Z_i = ek_ID_i
		
		# Scheme #
		s1_i, s2_i = self.__group.random(ZR), self.__group.random(ZR) # generate $s_{1_i}, s_{2_i} \in \mathbb{Z}_r$ randomly
		VVec = tuple(H2(Omega ** s[i]) for i in range(self.__n)) # $V_i \gets H_2(\Omega^{s_i}), \forall i \in \{1, 2, \cdots, n\}$
		C0_i = (g3 * H1(TP_i)) ** s_i # $C_{0_i} \gets (g_3 H_1(t_i || p_i))^{s_i}$
		C1_i = v1 ** (s_i - s1_i) # $C_{1_i} \gets v_1^{s_i - s_{1_i}}$
		C2_i = v2 ** s1_i # $C_{2_i} \gets v_2^{s_{1_i}}$
		C3_i = v3 ** (s_i - s2_i) # $C_{3_i} \gets v_2^{s_i - s_{2_i}}$
		C4_i = v4 ** s2_i # $C_{4_i} \gets v_2^{s_{1_i}}$
		aVec = self.__computeCoefficients(VVec) # compute $a_0, a_1, a_2, \cdots a_n$ s.t. $\forall x \in \mathbb{Z}_r$, we have $f(x) = \prod\limits_{i = 1}^n (x - V_i) = a_0 + \sum\limits_{i = 1}^n a_i x^i$
		alpha = self.__group.random(ZR) # generate $\alpha \in \mathbb{Z}_r$
		C1 = g1 ** alpha # $C_1 \gets g_1^\alpha$
		C2 = Z_i ** x_i * T ** alpha # $C_2 \gets Z_i^{x_i} T^\alpha$
		C3 = pair(T, S) ** alpha # $C_3 \gets e(T, S)^\alpha$
		C4 = H3(
			b"".join(self.__group.serialize(ele) for ele in (C0_i, C1_i, C2_i, C3_i, C4_i) + aVec[:-1] + (C1, C2, C3))
		) # $C_4 \gets H_3(C_{0_1} || C_{0_2} || \cdots || C_{0_n} || C_{1_1} || C_{1_2} || \cdots || C_{1_n} || \cdots || C_{4_1} || C_{4_2} || \cdots || C_{4_n} || a_0 || a_1 || \cdots || a_{n - 1} || C_1 || C_2 || C_3)$
		C5 = sk_ID_i * C4 + x_i # $C_5 \gets \textit{sk}_{\textit{ID}_i} C_4 + x_i$
		CT_TP_i = (C0_i, C1_i, C2_i, C3_i, C4_i, C1, C2, C3, C4, C5) # $\textit{CT}_{\textit{TPs}} \gets (C_{0_i}, C_{1_i}, C_{2_i}, C_{3_i}, C_{4_i}, C_1, C_2, C_3, C_4, C_5)$
		
		# Return #
		return CT_TP_i # \textbf{return} $\textit{CT}_{\textit{TP}_i}$
	def TokenGen(self:object, QTPi:tuple, skIDi:Element) -> tuple: # $\textbf{TokenGen}(\textit{QTP}_i, \textit{sk}_{\textit{ID}_i}) \to \textit{token}_i$
		# Checks #
		if not self.__flag:
			print("TokenGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``TokenGen`` subsequently. ")
			self.Setup()
		if isinstance(QTPi, bytes): # type check
			QTP_i = QTPi
		else:
			QTP_i = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("TokenGen: The variable $\\textit{QTP}_i$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(skIDi, Element) and skIDi.type == ZR: # type check
			sk_ID_i = skIDi
		else:
			sk_ID_i = self.KGen(self.__group.random(ZR), [])[0]
			print("TokenGen: The variable $\\textit{sk}_{\\textit{ID}_i}$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		g1, g2, g3, H1 = self.__mpk[0], self.__mpk[1], self.__mpk[2], self.__mpk[3]
		omega, t1, t2, t3, t4 = self.__msk[3], self.__msk[4], self.__msk[5], self.__msk[6], self.__msk[7]
		
		# Scheme #
		r1_i , r2_i = self.__group.random(ZR), self.__group.random(ZR) # generate $r_{1_i}, r_{2_i} \in \mathbb{Z}_r$ randomly
		T0_i = g2 ** (r1_i * t1 * t2 + r2_i * t3 * t4) # $T_{0_i} \gets g_2^{r_{1_i} t_1 t_2 + r_{2_i} t_3 t_4}$
		T1_i = g1 ** (omega * t2) * ((g3 * H1(QTP_i)) ** (-r1_i * t2)) # $T_{1_i} \gets g_1^{\omega t_2} (g_3 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{1_i} t_2}$
		T2_i = g1 ** (omega * t1) * ((g3 * H1(QTP_i)) ** (-r1_i * t1)) # $T_{2_i} \gets g_1^{\omega t_1} (g_3 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{1_i} t_1}$
		T3_i = (g3 * H1(QTP_i)) ** (-r2_i * t4) # $T_{3_i} \gets (g_3 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{2_i} t_4}$
		T4_i = (g3 * H1(QTP_i)) ** (-r2_i * t3) # $T_{4_i} \gets (g_3 H_1(\textit{qt}_i || \textit{qp}_i))^{-r_{2_i} t_3}$
		token_i = (T0_i, T1_i, T2_i, T3_i, T4_i) # $\textit{token} \gets (T_{0_i}, T_{1_i}, T_{2_i}, T_{3_i}, T_{4_i})$
		
		# Return #
		return token_i # \textbf{return} $\textit{token}_i$
	def Query(self:object, CTTPi:tuple, tokeni:tuple, _s:tuple|list) -> bool: # $\textbf{Query}(\textit{CT}_{\textit{TP}_i}, \textit{token}_i, s) \to y, y \in \{0, 1\}$
		# Checks #
		if not self.__flag:
			print("Query: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Query`` subsequently. ")
			self.Setup()
		if isinstance(_s, (tuple, list)) and len(_s) == self.__n and all(isinstance(ele, Element) and ele.type == ZR for ele in _s):
			s = _s
		else:
			s = tuple(self.__group.random(ZR) for _ in range(self.__n))
			print("Query: The variable $s$ should be a tuple or a list containing $n$ elements of \\mathbb{Z}_r, but it is not, which has been generated randomly. ")
		if not (isinstance(CTTPi, tuple) and len(CTTPi) == 10 and all(isinstance(ele, Element) for ele in CTTPi)):
			return False
		if not (isinstance(tokeni, tuple) and len(tokeni) == 5 and all(isinstance(ele, Element) for ele in tokeni)):
			return False
		
		# Unpack #
		H2, Omega = self.__mpk[4], self.__mpk[10]
		C0_i, C1_i, C2_i, C3_i, C4_i = CTTPi[0], CTTPi[1], CTTPi[2], CTTPi[3], CTTPi[4]
		T0_i, T1_i, T2_i, T3_i, T4_i = tokeni
		
		# Scheme #
		try:
			VVec = tuple(H2(Omega ** s[i]) for i in range(self.__n))
			aVec = self.__computeCoefficients(VVec)
			VPrime_i = H2(pair(C0_i, T0_i) * pair(T1_i, C1_i) * pair(T2_i, C2_i) * pair(T3_i, C3_i) * pair(T4_i, C4_i))
			return self.__computePolynomial(VPrime_i, aVec) == self.__group.init(ZR, 0)
		except Exception:
			return False
	def Trace(self:object, CTTPi:tuple, _L:list) -> tuple|bool: # $\textbf{Trace}(\textit{TP}_{\textit{TP}_i}, L) \to \textit{identity}$
		# Checks #
		if not self.__flag:
			print("Trace: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Trace`` subsequently. ")
			self.Setup()
		if not (isinstance(CTTPi, tuple) and len(CTTPi) == 10 and all(isinstance(ele, Element) for ele in CTTPi)):
			return False
		if not isinstance(_L, list):
			return False
		
		# Unpack #
		H4 = self.__mpk[6]
		t = self.__msk[2]
		C1, C2 = CTTPi[5], CTTPi[6]
		
		# Scheme #
		try:
			tag_i = H4(C2 / (C1 ** t))
		except Exception:
			return False
		for element in _L:
			if isinstance(element, tuple) and len(element) == 3 and tag_i == element[2]:
				return element
		
		# Return #
		return False
	def getLengthOf(self:object, obj:Element|int|bytes|tuple|list|set|dict|str) -> int|str:
		if isinstance(obj, Element):
			return len(self.__group.serialize(obj))
		elif isinstance(obj, int) or callable(obj):
			return (self.__group.secparam + 7) >> 3
		elif isinstance(obj, str):
			return len(obj.encode('utf-8'))
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


def conductScheme(curveParameter:tuple|list|dict|str, n:int = 30, m:int = 10, run:int|None = None, isVerbose:bool = False) -> list:
	# Begin #
	curveName, securityParameter, runString = "N/A", 512, "N/A"
	isSystemValid, isBSchemeCorrect, isSchemeCorrect, isTracingVerified = (False, ) * 4
	timeBSetup, timeBKGen, timeBEncryption, timeBTokenGen, timeBQuery = ("N/A", ) * 5
	timeSetup, timeKGen, timeEncryption, timeTokenGen, timeQuery, timeTrace = ("N/A", ) * 6
	sizeZR, sizeG1, sizeG2, sizeGT = ("N/A", ) * 4
	sizeBpk, sizeBsk, sizeBskIDs, sizeBCTTPs, sizeBTokens = ("N/A", ) * 5
	sizeMpk, sizeMsk, sizeSkIDs, sizeEkIDs, sizeCTTPs, sizeTokens = ("N/A", ) * 6
	
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
	if isinstance(m, int):
		mString = m
	else:
		flag = False
	if isinstance(run, int) and run >= 1:
		runString = run
	if isVerbose is not False:
		print("Curve: ({0}, {1})".format(curveName, securityParameter))
		print("$n$:", nString)
		print("$m$:", mString)
		print("run:", runString)
	if flag and 1 <= m <= n:
		try:
			group = PairingGroup(curveName, secparam = securityParameter)
			pair(group.random(G1), group.random(G2))
			isSystemValid = True
			if isVerbose is not False:
				print("Is the system valid? Yes. ")
		except BaseException as e:
			if isVerbose is not False:
				print("Is the system valid? No. Failed to create the ``PairingGroup`` instance due to {0}. ".format(repr(e)))
				print()
	elif isVerbose is not False:
		print("Is the system valid? No. The parameters $m$ and $n$ should be two positive integers satisfying $1 \\leqslant m \\leqslant n$. ")
		print()
	
	# Execution #
	if isSystemValid:
		# Initialization #
		scheme = SchemeCANIPSI(group)
		sizeZR, sizeG1, sizeG2, sizeGT = (
			scheme.getLengthOf(group.random(ZR)), scheme.getLengthOf(group.random(G1)), 
			scheme.getLengthOf(group.random(G2)), scheme.getLengthOf(group.random(GT))
		)

		try:
			pair(group.random(G1), group.random(G1))
			isAsymmetric = False
		except:
			isAsymmetric = True

		if isAsymmetric:
			isBSchemeCorrect = "N/A"
		else:
			# BSetup #
			startTime = perf_counter()
			bpk, bsk = scheme.BSetup(n, m)
			endTime = perf_counter()
			timeBSetup = endTime - startTime
			sizeBpk, sizeBsk = scheme.getLengthOf(bpk), scheme.getLengthOf(bsk)

			# BKGen #
			startTime = perf_counter()
			IDVec, bsk_IDs = tuple(group.random(ZR) for _ in range(n)), []
			for i in range(n):
				bsk_IDs.append(scheme.BKGen(IDVec[i]))
			endTime = perf_counter()
			timeBKGen = (endTime - startTime) / n
			sizeBskIDs = scheme.getLengthOf(bsk_IDs)

			# BEncryption #
			startTime = perf_counter()
			TPs = tuple(randbelow(1 << group.secparam).to_bytes((group.secparam + 7) >> 3, byteorder = "big") for _ in range(n))
			s = tuple(group.random(ZR) for _ in range(n))
			BCT_TPs = []
			for i in range(n):
				BCT_TPs.append(scheme.BEncryption(TPs[i], s, s[i]))
			endTime = perf_counter()
			timeBEncryption = (endTime - startTime) / n
			sizeBCTTPs = scheme.getLengthOf(BCT_TPs)

			# BTokenGen #
			startTime = perf_counter()
			QTP = TPs[:m]
			BTokens = []
			for i in range(m):
				BTokens.append(scheme.BTokenGen(QTP[i], bsk_IDs[i]))
			endTime = perf_counter()
			timeBTokenGen = (endTime - startTime) / m
			sizeBTokens = scheme.getLengthOf(BTokens)

			# BQuery #
			startTime = perf_counter()
			bys = []
			for i in range(m):
				bys.append(scheme.BQuery(BCT_TPs[i], BTokens[i]))
			endTime = perf_counter()
			isBSchemeCorrect = bys and all(bys)
			timeBQuery = (endTime - startTime) / m
		
		# Setup #
		startTime = perf_counter()
		mpk, msk = scheme.Setup(n, m)
		endTime = perf_counter()
		timeSetup = endTime - startTime
		sizeMpk, sizeMsk = scheme.getLengthOf(mpk), scheme.getLengthOf(msk)
		
		# KGen #
		startTime = perf_counter()
		IDVec, L, sk_IDs, ek_IDs = tuple(group.random(ZR) for _ in range(n)), [], [], []
		for i in range(n):
			sk_ID_i, ek_ID_i = scheme.KGen(IDVec[i], L)
			sk_IDs.append(sk_ID_i)
			ek_IDs.append(ek_ID_i)
		endTime = perf_counter()
		timeKGen = (endTime - startTime) / n
		sizeSkIDs = scheme.getLengthOf(sk_IDs)
		sizeEkIDs = scheme.getLengthOf(ek_IDs)
		
		# Encryption #
		startTime = perf_counter()
		TPs = tuple(randbelow(1 << group.secparam).to_bytes((group.secparam + 7) >> 3, byteorder = "big") for _ in range(n))
		s = tuple(group.random(ZR) for _ in range(n))
		CT_TPs = []
		for i in range(n):
			CT_TPs.append(scheme.Encryption(TPs[i], sk_IDs[i], ek_IDs[i], s, s[i]))
		endTime = perf_counter()
		timeEncryption = (endTime - startTime) / n
		sizeCTTPs = scheme.getLengthOf(CT_TPs)
		
		# TokenGen #
		startTime = perf_counter()
		QTP = TPs[:m]
		Tokens = []
		for i in range(m):
			Tokens.append(scheme.TokenGen(QTP[i], sk_IDs[i]))
		endTime = perf_counter()
		timeTokenGen = (endTime - startTime) / m
		sizeTokens = scheme.getLengthOf(Tokens)
		
		# Query #
		startTime = perf_counter()
		ys = []
		for i in range(m):
			ys.append(scheme.Query(CT_TPs[i], Tokens[i], s))
		endTime = perf_counter()
		isSchemeCorrect = ys and all(ys)
		timeQuery = (endTime - startTime) / m
		
		# Trace #
		startTime = perf_counter()
		identities = []
		for i in range(m):
			identities.append(scheme.Trace(CT_TPs[i], L))
		endTime = perf_counter()
		isTracingVerified = identities and all(identity is not False for identity in identities)
		timeTrace = (endTime - startTime) / m
		
		# Destruction #
		del scheme
		if isVerbose is not False:
			print("bys:", "N/A" if isAsymmetric else bys)
			print("ys:", ys)
			print("identities:", identities)
			print("Is the basic scheme correct? {0}. ".format("Yes" if isBSchemeCorrect else "No"))
			print("Is the scheme correct? {0}. ".format("Yes" if isSchemeCorrect else "No"))
			print("Is the tracing verified? {0}. ".format("Yes" if isTracingVerified else "No"))
			print("Time:", (
				(timeBSetup, timeBKGen, timeBEncryption, timeBTokenGen, timeBQuery), 
				(timeSetup, timeKGen, timeEncryption, timeTokenGen, timeQuery, timeTrace)
			))
			print("Space:", (sizeZR, sizeG1, sizeG2, sizeGT, 
				(sizeBpk, sizeBsk, sizeBskIDs, sizeBCTTPs, sizeBTokens), 
				(sizeMpk, sizeMsk, sizeSkIDs, sizeEkIDs, sizeCTTPs, sizeTokens)
			))
			print()
	
	# End #
	return [
		Parser.getSchemeName(), curveName, securityParameter, nString, mString, runString, 
		isSystemValid, isBSchemeCorrect, isSchemeCorrect, isTracingVerified, 
		timeBSetup, timeBKGen, timeBEncryption, timeBTokenGen, timeBQuery, 
		timeSetup, timeKGen, timeEncryption, timeTokenGen, timeQuery, timeTrace, 
		sizeZR, sizeG1, sizeG2, sizeGT, 
		sizeBpk, sizeBsk, sizeBskIDs, sizeBCTTPs, sizeBTokens, 
		sizeMpk, sizeMsk, sizeSkIDs, sizeEkIDs, sizeCTTPs, sizeTokens
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
			queries = ("scheme", "curveName", "secparam", "n", "m", "runCount")
			validators = ("isSystemValid", "isBSchemeCorrect", "isSchemeCorrect", "isTracingVerified")
			metrics = (
				"BSetup (s)", "BKGen (s)", "BEncryption (s)", "BTokenGen (s)", "BQuery (s)", 
				"Setup (s)", "KGen (s)", "Encryption (s)", "TokenGen (s)", "Query (s)", "Trace (s)", 
				"elementOfZR (B)", "elementOfG1 (B)", "elementOfG2 (B)", "elementOfGT (B)", 
				"bpk (B)", "bsk (B)", "bsk_IDs (B)", "BCT_TPs (B)", "BTokens (B)", 
				"mpk (B)", "msk (B)", "sk_IDs (B)", "ek_IDs (B)", "CT_TPs (B)", "Tokens (B)"
			)
			getValidatorJudges = lambda x:(x[queryLength + validatorIndex] for validatorIndex in (0, 2, 3))
			getMetricJudges = lambda x:(x[queryValidatorLength + metricIndex] for metricIndex in (5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 20, 21, 22, 23, 24, 25))
			
			# Scheme #
			columns, queryLength, results = queries + validators + metrics, len(queries), []
			length, queryValidatorLength, runCountIndex = len(columns), queryLength + len(validators), queryLength - 1
			saver = Saver(outputFilePath, columns, decimalPlace = decimalPlace, encoding = encoding)
			try:
				for curveParameter in curveParameters:
					for n in range(10, 31, 5):
						for m in range(5, n, 5):
							averages = conductScheme(curveParameter, n = n, m = m, run = 1, isVerbose = isVerbose)
							for run in range(2, runCount + 1):
								result = conductScheme(curveParameter, n = n, m = m, run = run, isVerbose = isVerbose)
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