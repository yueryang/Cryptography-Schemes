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
	__SchemeName = "SchemeIBBME" # splitext(basename(__file__))[0]
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
		print("This is a possible implementation of the IBBME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ")
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

class SchemeIBBME:
	__DefaultL = 30
	def __init__(self:object, group:None|PairingGroup = None) -> object: # This scheme is applicable to symmetric and asymmetric groups of prime orders. 
		self.__group = group if isinstance(group, PairingGroup) else PairingGroup("SS512", secparam = 512)
		if self.__group.secparam < 1:
			self.__group = PairingGroup(self.__group.groupType())
			print("Init: The securtiy parameter should be a positive integer, but it is not, which has been defaulted to {0}. ".format(self.__group.secparam))
		self.__operand = (1 << self.__group.secparam) - 1 # use to cast binary strings
		self.__l = SchemeIBBME.__DefaultL
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
	def Setup(self:object, l:int = __DefaultL) -> tuple: # $\textbf{Setup}() \to (\textit{mpk}, \textit{msk})$
		# Checks #
		self.__flag = False
		if isinstance(l, int) and l >= 1: # boundary check
			self.__l = l
		else:
			self.__l = SchemeIBBME.__DefaultL
			print("Setup: The variable $l$ should be a positive integer, but it is not, which has been defaulted to ${0}$. ".format(SchemeIBBME.__DefaultL))
		
		# Scheme #
		g, v = self.__group.random(G1), self.__group.random(G1) # generate $g, v \in \mathbb{G}_1$ randomly
		h = self.__group.random(G2) # generate $h \in \mathbb{G}_2$ randomly
		rVec1 = tuple(self.__group.random(ZR) for _ in range(self.__l + 1)) # generate $\vec{r}_1 = (r_{1, 0}, r_{1, 1}, \cdots, r{1, l}) \in \mathbb{Z}_r^{l + 1}$ randomly
		rVec2 = tuple(self.__group.random(ZR) for _ in range(self.__l + 1)) # generate $\vec{r}_2 = (r_{2, 0}, r_{2, 1}, \cdots, r{2, l}) \in \mathbb{Z}_r^{l + 1}$ randomly
		t1, t2, beta1, beta2, alpha, rho, b = self.__group.random(ZR, 7) # generate $t_1, t_2, \beta_1, \beta_2, \alpha, \rho, b \in \mathbb{Z}_r$ randomly
		tau = self.__generateRandomNonZeroZRElement() # generate $\tau \in \mathbb{Z}_r^*$ randomly
		rVec = tuple(rVec1[i] + b * rVec2[i] for i in range(self.__l + 1)) # $\vec{r} \gets (r_0, r_1, \cdots, r_l) = \vec{r}_1 + b\vec{r}_2 = (r_{1, 0} + br_{2, 0}, r_{1, 1} + br_{2, 1}, \cdots, r_{1, l} + br_{2, l})$
		t = t1 + b * t2 # $t \gets t_1 + bt_2$
		beta = beta1 + b * beta2 # $\beta \gets \beta_1 + b\beta_2$
		RVec = tuple(g ** rVec[i] for i in range(self.__l + 1)) # $\vec{R} \gets g^{\vec{r}} = (g^{r_0}, g^{r_1}, \cdots, g^{r_l})$
		T = g ** t # $T \gets g^t$
		H0 = lambda x:self.__group.hash(x, G2) # $H_0: \{0, 1\}^* \to \mathbb{G}_2$
		H1 = lambda x:self.__group.hash(x, G1) # $H_1: \{0, 1\}^* \to \mathbb{G}_1$
		H2 = lambda x:self.__group.hash(x, ZR) # $H_2: \{0, 1\}^* \to \mathbb{Z}_r$
		H3 = lambda x:self.__group.hash(self.__group.serialize(x), ZR) # $H_3: \mathbb{G}_T \to \mathbb{Z}_r$
		self.__mpk = (
			v, v ** rho, g, g ** b, RVec, T, pair(g, h) ** beta, h, tuple(h ** rVec1[i] for i in range(l + 1)), tuple(h ** rVec2[i] for i in range(l + 1)), h ** t1, h ** t2, g ** (tau * beta), h ** (tau * beta1), h ** (tau * beta2), h ** (1 / tau), H0, H1, H2, H3
		) # $\textit{mpk} \gets (v, v^\rho, g, g^b, \vec{R}, T, e(g, h)^\beta, h, h^{\vec{r}_1}, h^{\vec{r}_2}, h^{t_1}, h^{t_2}, g^{\tau\beta}, h^{\tau\beta_1}, h^{\tau\beta_2}, h^{1/\tau}, H_0, H_1, H_2, H_3)$
		self.__msk = (h ** beta1, h ** beta2, alpha, rho) # $\textit{msk} \gets (h^{\beta_1}, h^{\beta_2}, \alpha, \rho)$
		
		# Return #
		self.__flag = True
		return (self.__mpk, self.__msk) # \textbf{return} $(\textit{mpk}, \textit{msk})$
	def EKGen(self:object, _idStar:bytes) -> Element: # $\textbf{EKGen}(\textit{id}^*) \to \textit{ek}_{\textit{id}^*}$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("EKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``EKGen`` subsequently. ")
		if isinstance(_idStar, bytes): # type check
			idStar = _idStar
		else:
			idStar = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("EKGen: The variable $\\textit{id}^*$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		
		# Unpack #
		H1 = self.__mpk[17]
		alpha = self.__msk[2]
		
		# Scheme #
		ek_idStar = H1(idStar) ** alpha # $\textit{ek}_{\textit{id}^*} \gets H_1(\textit{id}^*)^\alpha$
		
		# Return #
		return ek_idStar # \textbf{return} $\textit{ek}_{\textit{id}^*}$
	def DKGen(self:object, _identity:bytes) -> Element: # $\textbf{DKGen}(\textit{id}) \to \textit{dk}_\textit{id}$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("DKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``DKGen`` subsequently. ")
		if isinstance(_identity, bytes): # type check
			identity = _identity
		else:
			identity = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("DKGen: The variable $\\textit{id}$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		
		# Unpack #
		h, hToThePowerOfR1, hToThePowerOfR2, hToThePowerOfT1, hToThePowerOfT2, H0, H2 = self.__mpk[7], self.__mpk[8], self.__mpk[9], self.__mpk[10], self.__mpk[11], self.__mpk[16], self.__mpk[18]
		hToThePowerOfBeta1, hToThePowerOfBeta2, alpha, rho = self.__msk
		
		# Scheme #
		z = self.__group.random(ZR) # generate $z \in \mathbb{Z}_r$ randomly
		rtags = tuple(self.__group.random(ZR) for _ in range(self.__l)) # generate $\textit{rtags} = (\textit{rtag}_1, \textit{rtag}_2, \cdots, \textit{rtag}_l) \in \mathbb{Z}_r^l$ randomly
		dk1 = H0(identity) ** rho # $\textit{dk}_1 \gets H_0(\textit{id})^\rho$
		dk2 = H0(identity) ** alpha # $\textit{dk}_2 \gets H_0(\textit{id})^\alpha$
		dk3 = H0(identity) # $\textit{dk}_3 \gets H_0(\textit{id})$
		dk4 = hToThePowerOfBeta1 * hToThePowerOfT1 ** z # $\textit{dk}_4 \gets h^{\beta_1}(h^{t_1})^z$
		dk5 = hToThePowerOfBeta2 * hToThePowerOfT2 ** z # $\textit{dk}_5 \gets h^{\beta_2}(h^{t_2})^z$
		dk6 = h ** z # $\textit{dk}_6 \gets h^z$
		dk7 = tuple(
			(hToThePowerOfT1 ** rtags[j - 1] * hToThePowerOfR1[j] / hToThePowerOfR1[0] ** (H2(identity) ** j)) ** z for j in range(1, self.__l + 1)
		) # $\textit{dk}_{7, j} \gets ((h^{t_1})^{\textit{rtag}_j}h^{r_{1, j}} / (h^{r_{1, 0}})^{H_2(\textit{id})^j})^z, \forall j \in \{1, 2, \cdots, l\}$
		dk8 = tuple(
			(hToThePowerOfT2 ** rtags[j - 1] * hToThePowerOfR2[j] / hToThePowerOfR2[0] ** (H2(identity) ** j)) ** z for j in range(1, self.__l + 1)
		) # $\textit{dk}_{8, j} \gets ((h^{t_2})^{\textit{rtag}_j}h^{r_{2, j}} / (h^{r_{2, 0}})^{H_2(\textit{id})^j})^z, \forall j \in \{1, 2, \cdots, l\}$
		dk_id = (dk1, dk2, dk3, dk4, dk5, dk6, dk7, dk8, rtags) # $\textit{dk}_\textit{id} \gets (\textit{dk}_1, \textit{dk}_2, \cdots, \textit{dk}_8, \textit{rtags})$
		
		# Return #
		return dk_id # \textbf{return} $\textit{dk}_\textit{id}$
	def Enc(self:object, _S:tuple, ekidStar:Element, message:Element) -> tuple: # $\textbf{Enc}(S, \textit{ek}_{\textit{id}^*}, m) \to \textit{ct}$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("Enc: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Enc`` subsequently. ")
		if isinstance(_S, tuple) and _S and all(isinstance(ele, bytes) for ele in _S): # hybrid check
			S = _S
		else:
			S = tuple(randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big") for _ in range(self.__l))
			print("Enc: The variable $S$ should be a tuple containing $n = \\|S\\|$ ``bytes`` objects where the integer $n \\in [1, {0}]$, but it is not, which has been generated randomly with a length of $l = {0}$. ".format(self.__l))
		if isinstance(ekidStar, Element) and ekidStar.type == G1: # type check
			ek_idStar = ekidStar
		else:
			ek_idStar = self.EKGen(randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big"))
			print("Enc: The variable $\\textit{ek}_{\\textit{id}^*}$ should be an element of $\\mathbb{G}_1$, but it is not, which has been generated randomly. ")
		if isinstance(message, Element) and message.type == GT: # type check
			m = message
		else:
			m = self.__group.random(GT)
			print("Enc: The variable $m$ should be an element of $\\mathbb{G}_T$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		v, vToThePowerOfRho, g, gToThePowerOfB, R, T, eGHToThePowerOfBeta, H0, H2, H3 = self.__mpk[0], self.__mpk[1], self.__mpk[2], self.__mpk[3], self.__mpk[4], self.__mpk[5], self.__mpk[6], self.__mpk[16], self.__mpk[18], self.__mpk[19]
		n = len(S)
		
		# Scheme #
		y = self.__computeCoefficients(tuple(H2(ele) for ele in S)) # compute $y_0, y_1, y_2, \cdots y_n$ s.t. $\forall x \in \mathbb{Z}_r$, we have $F(x) = \prod\limits_{\textit{id}_j \in S} (x - H_2(\textit{id}_j)) = y_0 + \sum\limits_{i = 1}^n y_i x^i$
		yVec = y[:-1] + (self.__group.init(ZR, 1), ) + (self.__group.init(ZR, 0), ) * (self.__l - n) # $\vec{y} \gets (y_0, y_1, \cdots, y_n, y_{n + 1}, y_{n + 2}, \cdots, y_l) = (y_0, y_1, \cdots, y_n, 0, 0, \cdots, 0)$
		del y
		s, ctag = self.__group.random(ZR, 2) # generate $s, \textit{ctag} \in \mathbb{Z}_r$ randomly
		d2 = self.__generateRandomNonZeroZRElement() # generate $d_2 \in \mathbb{Z}_r^*$ randomly
		C0 = m * eGHToThePowerOfBeta ** s # $C_0 \gets m \cdot e(g, h)^{\beta s}$
		C1 = g ** s # $C_1 \gets g^s$
		C2 = gToThePowerOfB ** s # $C_2 \gets g^{bs}$
		C3 = (T ** ctag * self.__product(tuple(R[i] ** yVec[i] for i in range(n + 1)))) ** (d2 * s) # $C_3 \gets \left(T^{\textit{ctag}}\prod\limits_{i = 0}^n (g^{r_i})^{y_i}\right)^{d_2 s}$
		C4 = v ** s # $C_4 \gets v^s$
		V_id = tuple(H3(pair(H0(S[i]), ek_idStar * gToThePowerOfB ** s * vToThePowerOfRho ** s)) for i in range(n)) # $V_{\textit{id}_i} \gets H_3(e(H_0(\textit{id}_i), \textit{ek}_{\textit{id}^*} \cdot g^{bs} \cdot v^{\rho s})), \forall \textit{id}_i \in S$
		bVec = self.__computeCoefficients(
			V_id, k = d2
		) # compute $\vec{b} \gets (b_0, b_1, b_2, \cdots b_n)$ s.t. $\forall y \in \mathbb{Z}_r$, we have $g(y) = \prod\limits_{V_{\textit{id}_k} \in V_{\textit{id}}} (y - V_{\textit{id}_k}) + d_2 = b_0 + \sum\limits_{k = 1}^n b_k y^k$
		ct = (C0, C1, C2, C3, C4, ctag, yVec, bVec[:-1] + (self.__group.init(ZR, 1), )) # $\textit{ct} \gets (C_0, C_1, C_2, C_3, C_4, \textit{ctag}, \vec{y}, \vec{b})$
		
		# Return #
		return ct # \textbf{return} $\textit{ct}$
	def Dec(self:object, _S:tuple, dkidi:tuple, _idStar:bytes, cipherText:tuple) -> Element|bool: # $\textbf{Dec}(S, \textit{dk}_{\textit{id}_i}, \textit{id}^*, \textit{ct}) \to m$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("Dec: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Dec`` subsequently. ")
		if isinstance(_S, tuple) and _S and all(isinstance(ele, bytes) for ele in _S): # hybrid check
			S = _S
		else:
			S = tuple(randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big") for _ in range(self.__l))
			print("Dec: The variable $S$ should be a tuple containing $n = \\|S\\|$ ``bytes`` objects where the integer $n \\in [1, {0}]$, but it is not, which has been generated randomly with a length of $l = {0}$. ".format(self.__l))
		if isinstance(dkidi, tuple) and len(dkidi) == 9 and all(isinstance(ele, Element) for ele in dkidi[:6]) and all(isinstance(ele, tuple) for ele in dkidi[6:]): # hybrid check
			dk_id_i = dkidi
		else:
			dk_id_i = self.DKGen(randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big"))
			print("Dec: The variable $\\textit{dk}_{\\textit{id}_i}$ should be a tuple containing 6 elements and 3 tuples, but it is not, which has been generated randomly. ")
		if isinstance(_idStar, bytes): # type check
			idStar = _idStar
		else:
			idStar = randbelow(1 << self.__group.secparam).to_bytes((self.__group.secparam + 7) >> 3, byteorder = "big")
			print("Dec: The variable $\\textit{id}^*$ should be a ``bytes`` object, but it is not, which has been generated randomly. ")
		if isinstance(cipherText, tuple) and len(cipherText) == 8 and all(isinstance(ele, Element) for ele in cipherText[:6]) and isinstance(cipherText[-2], tuple) and isinstance(cipherText[-1], tuple): # hybrid check
			ct = cipherText
		else:
			ct = self.Enc(S, self.EKGen(idStar), self.__group.random(GT))
			print("Dec: The variable $\\textit{ct}$ should be a tuple containing 6 elements and 2 tuples, but it is not, which has been generated randomly. ")
		
		# Unpack #
		H0, H1, H3 = self.__mpk[16], self.__mpk[17], self.__mpk[19]
		n = len(S)
		dki1, dki2, dki3, dki4, dki5, dki6, dki7, dki8, rtags = dk_id_i
		C0, C1, C2, C3, C4, ctag, yVec, bVec = ct
		
		# Scheme #
		V_id_i = H3(pair(dki3, C2) * pair(dki2, H1(idStar)) * pair(dki1, C4)) # $V(\textit{id}_i) \gets H_3(e(\textit{dk}_{i, 3}, C_2)e(\textit{dk}_{i, 2}, H_1(\textit{id}^*))e(\textit{dk}_{i, 1}, C_4))$
		d2 = self.__computePolynomial(V_id_i, bVec) # $d_2 \gets g(V_{\textit{id}_i}) = b_0 + \sum\limits_{j = 1}^n b_j V_{\textit{id}_i}^j$
		if not (isinstance(d2, Element) and d2.type == ZR) or d2 == self.__group.init(ZR, 0):
			return False
		rtag = sum((yVec[i + 1] * rtags[i] for i in range(1, self.__l)), start = yVec[1] * rtags[0]) # $\textit{rtag} \gets \sum\limits_{i = 1}^l y_i \textit{rtags}_i$
		if rtag == ctag: # \textbf{if} $\textit{rtag} = \textit{ctag}$ \textbf{then}
			m = False # \quad$m \gets \perp$
		else: # \textbf{else}
			A = (
				pair(C1, self.__product(tuple(dki7[j] ** yVec[j + 1] for j in range(self.__l)))) * pair(C2, self.__product(tuple(dki8[j] ** yVec[j + 1] for j in range(self.__l)))) / pair(C3 ** (1 / d2), dki6)
			) # \quad$A \gets e\left(C_1, \prod\limits_{j = 1}^l \textit{dk}_{7, j}^{y_j}\right)e\left(C_2, \prod\limits_{j = 1}^l \textit{dk}_{8, j}^{y_j}\right) / e(C_3^{1 / d_2}, \textit{dk}_6)$
			B = pair(C1, dki4) * pair(C2, dki5) # \quad$B \gets e(C_1, \textit{dk}_4) \cdot e(C_2, \textit{dk}_5)$
			m = C0 * A ** (1 / (rtag - ctag)) * B ** (-1) # \quad$m \gets C_0 \cdot A^{1 / (\textit{rtag} - \textit{ctag})} \cdot B^{-1}$
		# \textbf{end if}
		
		# Return #
		return m # \textbf{return} $m$
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


def conductScheme(curveParameter:tuple|list|dict|str, l:int = 30, n:int = 10, _seed:int|None = None, run:int|None = None, isVerbose:bool = True) -> list:
	# Begin #
	curveName, securityParameter, lString, nString, runString = "N/A", 512, "N/A", "N/A", "N/A" # the default value of the security parameter in the Python Charm-Crypto framework is 512
	isSystemValid, isSchemeCorrect = False, False
	timeSetup, timeEKGen, timeDKGen, timeEnc, timeDec = ("N/A", ) * 5
	sizeZR, sizeG1, sizeG2, sizeGT = ("N/A", ) * 4
	sizeMpk, sizeMsk, sizeEkIdStar, sizeDkId, sizeCt = ("N/A", ) * 5
	seed = None
	
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
	if isinstance(l, int):
		lString = l
	else:
		flag = False
	if isinstance(n, int):
		nString = n
	else:
		flag = False
	if isinstance(run, int) and run >= 1:
		runString = run
	if isVerbose is not False:
		print("Curve: ({0}, {1})".format(curveName, securityParameter))
		print("$l$:", lString)
		print("$n$:", nString)
		print("run:", runString)
	if flag and 1 <= n <= l:
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
		seed = _seed if isinstance(_seed, int) and 0 <= _seed < n else randbelow(n)
	elif isVerbose is not False:
		print("Is the system valid? No. The parameter $l$ and $n$ should be two positive integers satisfying $1 \\leqslant n \\leqslant l$. ")
		print()
	
	# Execution #
	if isSystemValid:
		# Initialization #
		schemeIBBME = SchemeIBBME(group)
		sizeZR, sizeG1, sizeG2, sizeGT = (
			schemeIBBME.getLengthOf(group.random(ZR)), schemeIBBME.getLengthOf(group.random(G1)), 
			schemeIBBME.getLengthOf(group.random(G2)), schemeIBBME.getLengthOf(group.random(GT))
		)
		
		# Setup #
		startTime = perf_counter()
		mpk, msk = schemeIBBME.Setup(l = l)
		endTime = perf_counter()
		timeSetup = endTime - startTime
		sizeMpk, sizeMsk = schemeIBBME.getLengthOf(mpk), schemeIBBME.getLengthOf(msk)
		
		# EKGen #
		startTime = perf_counter()
		idStar = randbelow(1 << group.secparam).to_bytes((group.secparam + 7) >> 3, byteorder = "big")
		ek_idStar = schemeIBBME.EKGen(idStar)
		endTime = perf_counter()
		timeEKGen = endTime - startTime
		sizeEkIdStar = schemeIBBME.getLengthOf(ek_idStar)
		
		# DKGen #
		startTime = perf_counter()
		identity = randbelow(1 << group.secparam).to_bytes((group.secparam + 7) >> 3, byteorder = "big")
		dk_id = schemeIBBME.DKGen(identity)
		endTime = perf_counter()
		timeDKGen = endTime - startTime
		sizeDkId = schemeIBBME.getLengthOf(dk_id)
		
		# Enc #
		startTime = perf_counter()
		S = (
			tuple(randbelow(1 << group.secparam).to_bytes((group.secparam + 7) >> 3, byteorder = "big") for _ in range(seed)) + (identity, )
			+ tuple(randbelow(1 << group.secparam).to_bytes((group.secparam + 7) >> 3, byteorder = "big") for _ in range(n - seed - 1))
		)
		message = group.random(GT)
		ct = schemeIBBME.Enc(S, ek_idStar, message)
		endTime = perf_counter()
		timeEnc = endTime - startTime
		sizeCt = schemeIBBME.getLengthOf(ct)
		
		# Dec #
		startTime = perf_counter()
		m = schemeIBBME.Dec(S, dk_id, idStar, ct)
		endTime = perf_counter()
		isSchemeCorrect = m == message
		timeDec = endTime - startTime
		
		# Destruction #
		del schemeIBBME
		if isVerbose is not False:
			print("Original:", message)
			print("Decrypted:", m)
			print("Is the scheme correct (m == message)? {0}. ".format("Yes" if isSchemeCorrect else "No"))
			print("Time:", (timeSetup, timeEKGen, timeDKGen, timeEnc, timeDec))
			print("Space:", (sizeZR, sizeG1, sizeG2, sizeGT, sizeMpk, sizeMsk, sizeEkIdStar, sizeDkId, sizeCt))
			print()
	
	# End #
	return [
		Parser.getSchemeName(), curveName, securityParameter, lString, nString, runString, 
		isSystemValid, isSchemeCorrect, 
		timeSetup, timeEKGen, timeDKGen, timeEnc, timeDec, 
		sizeZR, sizeG1, sizeG2, sizeGT, 
		sizeMpk, sizeMsk, sizeEkIdStar, sizeDkId, sizeCt
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
			queries = ("scheme", "curveName", "secparam", "l", "n", "runCount")
			validators = ("isSystemValid", "isSchemeCorrect")
			metrics = (
				"Setup (s)", "EKGen (s)", "DKGen (s)", "Enc (s)", "Dec (s)", 
				"elementOfZR (B)", "elementOfG1 (B)", "elementOfG2 (B)", "elementOfGT (B)", 
				"mpk (B)", "msk (B)", "ek_idStar (B)", "dk_id (B)", "ct (B)"
			)
			getValidatorJudges = lambda x:x[queryLength:queryValidatorLength]
			getMetricJudges = lambda x:x[queryValidatorLength:]
			
			# Scheme #
			columns, queryLength, results = queries + validators + metrics, len(queries), []
			length, queryValidatorLength, runCountIndex = len(columns), queryLength + len(validators), queryLength - 1
			saver = Saver(outputFilePath, columns, decimalPlace = decimalPlace, encoding = encoding)
			try:
				for curveParameter in curveParameters:
					for l in range(5, 31, 5):
						for n in range(5, l + 1, 5):
							averages = conductScheme(curveParameter, l = l, n = n, run = 1, isVerbose = isVerbose)
							for run in range(2, runCount + 1):
								result = conductScheme(curveParameter, l = l, n = n, run = run, isVerbose = isVerbose)
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