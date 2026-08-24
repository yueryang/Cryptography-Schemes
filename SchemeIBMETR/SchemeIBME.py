from os import chdir, makedirs, name, sep
from os.path import abspath, basename, dirname, exists, isfile, isdir, join, split, splitext
from sys import argv, exit
try:
	from charm.toolbox.pairinggroup import PairingGroup, G1, GT, ZR, pair, pc_element as Element
except:
	PairingGroup, G1, GT, ZR, pair, Element = (None, ) * 6
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
	__SchemeName = "SchemeIBME" # splitext(basename(__file__))[0]
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
		print("This is a possible implementation of the IBME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ")
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
class SchemeIBME:
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
		self.__operand = (1 << self.__group.secparam) - 1 # use to cast binary strings
		self.__mpk = None
		self.__msk = None
		self.__flag = False # to indicate whether it has already set up
	def Setup(self:object) -> tuple: # $\textbf{Setup}() \to (\textit{mpk}, \textit{msk})$
		# Checks #
		self.__flag = False
		
		# Scheme #
		r, s = self.__group.random(ZR), self.__group.random(ZR) # generate $r, s \in \mathbb{Z}_r$ randomly
		P = self.__group.init(G1, 1) # $P \gets 1{\mathbb{G}_1}$
		P0 = r * P # $P_0 \gets r \cdot P$
		H = lambda x:self.__group.hash(x, G1) # $H_1: \mathbb{Z}_r \to \mathbb{G}_1$
		mask = bytes([randbelow(256) for _ in range(len(self.__group.serialize(self.__group.random(ZR))))]) # generate $\textit{mask}, \|\textit{mask}\| \gets \|e\|, e \in \mathbb{Z}_r$ randomly
		HPrime = lambda x:self.__group.hash(bytes([a ^ b for a, b in zip(self.__group.serialize(x), mask)]), G1) # $H': \mathbb{Z}_r \oplus \textit{mask} \to \mathbb{G}_1$
		self.__mpk = (P, P0, H, HPrime) # $\textit{mpk} \gets (P, P_0, H, H')$
		self.__msk = (r, s) # $\textit{msk} \gets (r, s)$
		
		# Return #
		self.__flag = True
		return (self.__mpk, self.__msk) # \textbf{return} $(\textit{mpk}, \textit{msk})$
	def SKGen(self:object, sender:Element) -> Element: # $\textbf{SKGen}(S) \to \textit{ek}_S$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("SKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``SKGen`` subsequently. ")
		if isinstance(sender, Element) and sender.type == ZR: # type check
			S = sender
		else:
			S = self.__group.random(ZR)
			print("SKGen: The variable $S$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		HPrime = self.__mpk[-1]
		s = self.__msk[1]
		
		# Scheme #
		ek_S = s * HPrime(S) # $\textit{ek}_S \gets s \cdot H'(S)$
		
		# Return #
		return ek_S # \textbf{return} $\textit{ek}_S$
	def RKGen(self:object, receiver:Element) -> Element: # $\textbf{RKGen}(S) \to \textit{dk}_R$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("RKGen: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``RKGen`` subsequently. ")
		if isinstance(receiver, Element) and receiver.type == ZR: # type check
			R = receiver
		else:
			R = self.__group.random(ZR)
			print("RKGen: The variable $R$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		
		# Unpack #
		H = self.__mpk[-2]
		r, s = self.__msk
		
		# Scheme #
		H_R = H(R) # $H_R \gets H(R)$
		dk1 = r * H_R # $\textit{dk}_1 \gets r \cdot H_R$
		dk2 = s * H_R # $\textit{dk}_2 \gets s \cdot H_R$
		dk3 = H_R # $\textit{dk}_3 \gets H_R$
		dk_R = (dk1, dk2, dk3) # $\textit{dk}_R \gets (\textit{dk}_1, \textit{dk}_2, \textit{dk}_3)$
		
		# Return #
		return dk_R # \textbf{return} $\textit{dk}_R$
	def Enc(self:object, ekS:Element, receiver:Element, message:int|bytes) -> tuple: # $\textbf{Enc}(\textit{ek}_S, R, M) \to C$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("Enc: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Enc`` subsequently. ")
		if isinstance(ekS, Element) and ekS.type == G1: # type check
			ek_S = ekS
		else:
			ek_S = self.SKGen(self.__group.random(ZR))
			print("Enc: The variable $\\textit{ek}_S$ should be an element of $\\mathbb{G}_1$, but it is not, which has been generated randomly. ")
		if isinstance(receiver, Element) and receiver.type == ZR: # type check
			R = receiver
		else:
			R = self.__group.random(ZR)
			print("Enc: The variable $R$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		if isinstance(message, int) and message >= 0: # type check
			M = message & self.__operand
			if message != M:
				print("Enc: The passed message (int) is too long, which has been cast. ")
		elif isinstance(message, bytes):
			M = int.from_bytes(message, byteorder = "big") & self.__operand
			if len(message) << 3 > self.__group.secparam:
				print("Enc: The passed message (bytes) is too long, which has been cast. ")
		else:
			M = int.from_bytes(b"SchemeIBME", byteorder = "big") & self.__operand
			print("Enc: The variable $M$ should be an integer or a ``bytes`` object, but it is not, which has been defaulted to b\"SchemeIBME\". ")
		
		# Unpack #
		H = self.__mpk[-2]
		P, P0 = self.__mpk[0], self.__mpk[1]
		
		# Scheme #
		u, t = self.__group.random(ZR), self.__group.random(ZR) # generate $u, t \in \mathbb{Z}_r$ randomly
		T = t * P # $T \gets t \cdot P$
		U = u * P # $U \gets u \cdot P$
		H_R = H(R) # $H_R \gets H(R)$
		k_R = pair(H_R, u * P0) # $k_R \gets e(H_R, u \cdot P_0)$
		k_S = pair(H_R, T + ek_S) # $k_S \gets e(H_R, T + \textit{ek}_S)$
		V = M ^ int.from_bytes(self.__group.serialize(k_R), byteorder = "big") ^ int.from_bytes(self.__group.serialize(k_S), byteorder = "big") # $V \gets M \oplus k_R \oplus k_S$
		C = (T, U, V) # $C \gets (T, U, V)$
		
		# Return #
		return C # \textbf{return} $C$	
	def Dec(self:object, dkR:tuple, sender:Element, cipher:tuple) -> int: # $\textbf{Dec}(\textit{dk}_R, S, C) \to M$
		# Checks #
		if not self.__flag:
			self.Setup()
			print("Dec: The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``Dec`` subsequently. ")
		if isinstance(dkR, tuple) and len(dkR) == 3 and all(isinstance(ele, Element) for ele in dkR): # hybrid check
			dk_R = dkR
		else:
			dk_R = self.RKGen(self.__group.random(ZR))
			print("Dec: The variable $\\textit{dk}_R$ should be a tuple containing 3 elements, but it is not, which has been generated randomly. ")
		if isinstance(sender, Element) and sender.type == ZR: # type check
			S = sender
		else:
			S = self.__group.random(ZR)
			print("Dec: The variable $S$ should be an element of $\\mathbb{Z}_r$, but it is not, which has been generated randomly. ")
		if isinstance(cipher, tuple) and len(cipher) == 3 and isinstance(cipher[0], Element) and isinstance(cipher[1], Element) and isinstance(cipher[2], int): # hybrid check
			C = cipher
		else:
			C = self.Enc(self.SKGen(self.__group.random(ZR)), self.__group.random(ZR), b"SchemeIBME")
			print("Dec: The variable $C$ should be a tuple containing 2 elements and an ``int`` object, but it is not, which has been generated randomly. ")
		
		# Unpack #
		HPrime = self.__mpk[-1]
		dk1, dk2, dk3 = dk_R
		T, U, V = C
		
		# Scheme #
		k_R = pair(dk1, U) # $k_R \gets e(\textit{dk}_1, U)$
		HPrime_S = HPrime(S) # $H'_S \gets H'(S)$
		k_S = pair(dk3, T) * pair(HPrime_S, dk2) # $k_S \gets e(\textit{dk}_3, T)$
		M = V ^ int.from_bytes(self.__group.serialize(k_R), byteorder = "big") ^ int.from_bytes(self.__group.serialize(k_S), byteorder = "big") # $M \gets V \oplus k_R \oplus k_S$
		
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


def conductScheme(curveParameter:tuple|list|dict|str, run:int|None = None, isVerbose:bool = True) -> list:
	# Begin #
	curveName, securityParameter, runString = "N/A", 512, "N/A" # the default value of the security parameter in the Python Charm-Crypto framework is 512
	isSystemValid, isSchemeCorrect = False, False
	timeSetup, timeSKGen, timeRKGen, timeEnc, timeDec = ("N/A", ) * 5
	sizeZR, sizeG1G2, sizeGT = ("N/A", ) * 3
	sizeMpk, sizeMsk, sizeEkS, sizeDkR, sizeC = ("N/A", ) * 5
	
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
			pair(group.random(G1), group.random(G1))
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
		schemeIBME = SchemeIBME(group)
		sizeZR, sizeG1G2, sizeGT = schemeIBME.getLengthOf(group.random(ZR)), schemeIBME.getLengthOf(group.random(G1)), schemeIBME.getLengthOf(group.random(GT))
		
		# Setup #
		startTime = perf_counter()
		mpk, msk = schemeIBME.Setup()
		endTime = perf_counter()
		timeSetup = endTime - startTime
		sizeMpk, sizeMsk = schemeIBME.getLengthOf(mpk), schemeIBME.getLengthOf(msk)
		
		# SKGen #
		startTime = perf_counter()
		S = group.random(ZR)
		ek_S = schemeIBME.SKGen(S)
		endTime = perf_counter()
		timeSKGen = endTime - startTime
		sizeEkS = schemeIBME.getLengthOf(ek_S)
		
		# RKGen #
		startTime = perf_counter()
		R = group.random(ZR)
		dk_R = schemeIBME.RKGen(R)
		endTime = perf_counter()
		timeRKGen = endTime - startTime
		sizeDkR = schemeIBME.getLengthOf(dk_R)
		
		# Enc #
		startTime = perf_counter()
		message = int.from_bytes(b"SchemeIBME", byteorder = "big")
		C = schemeIBME.Enc(ek_S, R, message)
		endTime = perf_counter()
		timeEnc = endTime - startTime
		sizeC = schemeIBME.getLengthOf(C)
		
		# Dec #
		startTime = perf_counter()
		M = schemeIBME.Dec(dk_R, S, C)
		endTime = perf_counter()
		isSchemeCorrect = M == message
		timeDec = endTime - startTime
		
		# Destruction #
		del schemeIBME
		if isVerbose is not False:
			print("Original:", message)
			print("Decrypted:", M)
			print("Is the scheme correct (M == message)? {0}. ".format("Yes" if isSchemeCorrect else "No"))
			print("Time:", (timeSetup, timeSKGen, timeRKGen, timeEnc, timeDec))
			print("Space:", (sizeZR, sizeG1G2, sizeGT, sizeMpk, sizeMsk, sizeEkS, sizeDkR, sizeC))
			print()
	
	# End #
	return [
		Parser.getSchemeName(), curveName, securityParameter, runString, 
		isSystemValid, isSchemeCorrect, 
		timeSetup, timeSKGen, timeRKGen, timeEnc, timeDec, 
		sizeZR, sizeG1G2, sizeGT, 
		sizeMpk, sizeMsk, sizeEkS, sizeDkR, sizeC
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
			queries = ("scheme", "curveName", "secparam", "runCount")
			validators = ("isSystemValid", "isSchemeCorrect")
			metrics = (
				"Setup (s)", "SKGen (s)", "RKGen (s)", "Enc (s)", "Dec (s)", 
				"elementOfZR (B)", "elementOfG1G2 (B)", "elementOfGT (B)", 
				"mpk (B)", "msk (B)", "ek_S (B)", "dk_R (B)", "C (B)"
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