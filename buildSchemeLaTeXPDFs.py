from os import chdir, makedirs, name, sep, walk
from os.path import abspath, basename, dirname, isdir, isfile, islink, join, split, splitdrive, splitext
from sys import argv, exit
from ast import literal_eval
try:
	from libcst import Add, Attribute, BinaryOperation, CSTNode, Call, ClassDef, ConcatenatedString, EmptyLine, FunctionDef, Name, SimpleString, TrailingWhitespace, parse_module
except:
	Attribute, CSTNode, Call, ClassDef, ConcatenatedString, EmptyLine, FunctionDef, Name, SimpleString, TrailingWhitespace, parse_module = (None, ) * 11
from getpass import getpass
from re import match
from subprocess import TimeoutExpired, run
from time import perf_counter, sleep
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
	__DefaultOutput = "%p/%nLaTeX/%n"
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
		print("This is the official cryptographic scheme LaTeX and PDF builder. ")
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

class Builder:
	__DefaultCompilationTimeout = 10
	__GenerationDiagnostics = {"":[], "Saver":[], "Function":[]}
	def __init__(self:object, schemeFilePath:str, pathWithoutExtensions:str, collectionMode:bool = False) -> object:
		self.__schemeFilePath = schemeFilePath
		if isinstance(self.__schemeFilePath, str) and isinstance(pathWithoutExtensions, str):
			self.__schemeLaTeXFilePath = pathWithoutExtensions + ".tex"
			self.__targetDirectoryPath, self.__schemeLaTeXFileName = split(self.__schemeLaTeXFilePath)
			self.__schemePDFFilePath = pathWithoutExtensions + ".pdf"
			self.__flag = 1
		else:
			self.__schemeLaTeXFilePath = None
			self.__targetDirectoryPath = None
			self.__schemeLaTeXFileName = None
			self.__schemePDFFilePath = None
			self.__flag = 0
		self.__collectionMode = True == collectionMode
		self.__generationDiagnostics = None
		self.__generationTimeConsumption = None
		self.__compilationDiagnostics = None
		self.__compilationTimeConsumption = None
	def __evaluateString(self:object, expression:CSTNode) -> str|None:
		if isinstance(expression, (ConcatenatedString, SimpleString)):
			return expression.evaluated_value
		elif (
			isinstance(expression, Call) and isinstance(expression.func, Attribute)
			and "format" == expression.func.attr.value
		):
			return self.__evaluateString(expression.func.value)
		elif isinstance(expression, BinaryOperation) and isinstance(expression.operator, Add):
			leftString = self.__evaluateString(expression.left)
			rightString = self.__evaluateString(expression.right)
			if isinstance(leftString, str) and isinstance(rightString, str):
				return leftString + rightString
		return None
	def __checkString(self:object, string:str) -> bool:
		if self.__collectionMode:
			if string not in Builder.__GenerationDiagnostics[""]:
				Builder.__GenerationDiagnostics[""].append(string)
			return True
		elif string in (
			"", "\t{0}\t\tDisable the verbose console outputs. ", "\t{0}\t\tIndicate to confirm the overwriting of the existing output file. ", 
			"\t{0}\t\tPrint this help document. ", "\t{0} [1|2|5|10|20|50|100|...]\t\tSpecify the run count, which must be a positive integer. The default value is {1}. ", (
				"\t{0} [0|0.1|1|10|...|inf]\t\tSpecify the waiting time before exiting, which should be non-negative. "
				+ "Passing inf requires users to manually press the Enter key before exiting. The default value is {0}. "
			), "\t{0} [s|ms|microsecond|ns|ps|0|3|6|9|12|...]\t\tSpecify the decimal place, which should be a non-negative integer. The default value is {1}. ", 
			"\t{0} [utf-8|utf-16|...]\t\tSpecify the encoding mode for CSV and TXT outputs. The default value is {1}. ", 
			"\t{0} [|.|./{1}.xlsx|./{1}.csv|...]\t\tSpecify the output file path, leaving it empty for console output. The default value is {2}. ", 
			"\rThe countdown is {0} second(s). ", "\rThe countdown is {{0:>{0}}} second(s). ", "$d$:", "$k$:", "$l$:", "$m$:", "$n$:", 
			"Curve: ({0}, {1})", "Dec1:", "Dec2:", "Decrypted:", "Derived:", "Is DKey Sanity? {0}. ", 
			"Is EKey Sanity? {0}. ", "Is ``Dec1`` passed (m == message)? {0}. ", "Is ``Dec2`` passed (m' == message)? {0}. ", "Is ``ProxyDec`` passed? {0}. ", 
			"Is ``ProxyEnc`` passed? {0}. ", "Is ``ReEnc`` passed? {0}. ", "Is the basic scheme correct? {0}. ", "Is the deriver passed (M' == message)? {0}. ", 
			"Is the scheme correct (M == message)? {0}. ", "Is the scheme correct (m == message)? {0}. ", "Is the scheme correct (result is not False)? {0}. ", "Is the scheme correct? {0}. ", 
			"Is the system valid? No. Failed to create the ``PairingGroup`` instance due to {0}. ", "Is the system valid? No. The parameter $d$ should be a positive integer. ", 
			"Is the system valid? No. The execution failed due to {0}. ", 
			"Is the system valid? No. The parameter $l$ and $n$ should be two positive integers satisfying $1 \\leqslant n \\leqslant l$. ", 
			"Is the system valid? No. The parameters $l$ and $k$ should be two positive integers satisfying $2 \\leqslant k < l$. ", 
			"Is the system valid? No. The parameters $l$, $m$, and $n$ should be three positive integers satisfying $2 \\leqslant m < l \\land 2 \\leqslant n < l$. ", 
			"Is the system valid? No. The parameters $m$ and $n$ should be two positive integers satisfying $1 \\leqslant m \\leqslant n$. ", 
			"Is the system valid? No. The parameters $m$, $n$, and $d$ should be three positive integers. ", 
			"Is the system valid? No. The parameters $n$ and $d$ should be two positive integers satisfying $2 \\leqslant d \\leqslant n$. ", 
			"Is the system valid? No. The parameters $n$, $k$, and $d$ should be three positive integers satisfying $1 \\leqslant d \\leqslant k \\leqslant n$. ", 
			"Is the system valid? Yes. ", "Is the tracing verified? {0}. ", "Is tracing 1 verified (M1 == message1)? {0}. ", "Is tracing 2 verified (M2 == message2)? {0}. ", 
			"No experiments were conducted. ", "Options (case-insensitive): ", "Original:", 
			"Parameters: (N = {0}, n = {1}, q = {2})", "Parameters: (n = {0}, m = {1}, q = {2})", "Parameters: (n = {0}, m = {1}, q = {2}, lS = {3}, lR = {4})", 
			"Parser: The extension name of the output file path passed is one of the protected extension names, which would be reset to the default extension {0}. ", 
			"Parser: The output file path passed looks like a directory, which would be connected with the default file name {0}. ", 
			"Parser: The path {0} exists not to be a regular file. ", "Please press the Enter key to exit ({0}). ", 
			"Please install the libraries via the active Python package manager (e.g., pip). ", "Please refer to https://github.com/JHUISI/charm if necessary. ", 
			"Please wait {0} second(s) for automatic exit, or exit manually, for example by pressing Ctrl + C ({1}). ", 
			"Please wait {0} second(s) for automatic exit, or exit manually, for example by pressing ``Ctrl + C`` ({1}). ", "Space:", 
			"The runtime environment of the Python Charm-Crypto framework is not correctly configured. ", 
			"The runtime environment of the Python NumPy and SymPy libraries is not correctly configured. ", 
			"The runtime environment of the Python NumPy library is not correctly configured. ", 
			"The execution has finished ({0}). ",
			"The execution has started. ", "The experiments were interrupted by users. Saved results are retained. ", "The experiments were interrupted by {0}. Saved results are retained. ", 
			"This cryptographic scheme will be executed in a limited mode. ", 
			"This is a possible implementation of the AIBE cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the ARES cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the CA-NI-PSI cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the Fuzzy-ME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the IBBME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the IBME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the IBMECH cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is a possible implementation of the IBPME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the AA-IB-ME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the AnonymousME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the CA-NI-FPPCT cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the coefficient computation cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework and the Python NumPy library. ", 
			"This is the official implementation of the FS-MUAEKS cryptographic scheme in the Python programming language based on the Python NumPy and SymPy libraries. ", 
			"This is the official implementation of the HIB-ME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the IBMEMR cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the IBMETR cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the IBPRME cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the LB-PEAKS cryptographic scheme in the Python programming language based on the Python NumPy and SymPy libraries. ", 
			"This is the official implementation of the PBAC cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official implementation of the VL-PSI-CA cryptographic scheme in the Python programming language based on the Python Charm-Crypto framework. ", 
			"This is the official simulation implementation of the FS-LLRS cryptographic scheme in the Python programming language based on the Python NumPy library. ",
			"This is the official simulation implementation of the LWE-PEKS cryptographic scheme in the Python programming language based on the Python NumPy library. ",
			"Time:", "Verify:", "bys:", "identities:", "run:", "ys:"
		):
			return True
		else:
			self.__generationDiagnostics[""].append("The statement {0} is not official. ".format(repr(string)))
			return False
	def __checkSaverString(self:object, string:str) -> bool:
		if self.__collectionMode:
			if string not in Builder.__GenerationDiagnostics["Saver"]:
				Builder.__GenerationDiagnostics["Saver"].append(string)
			return True
		elif "\t{0}" == string:
			return True
		elif not string.startswith("Saver: "):
			self.__generationDiagnostics["Saver"].append("The statement {0} should start with \"Saver: \". ".format(repr(string)))
			return False
		elif string[7:] in (
			"Failed to initialize the directory for the output file path {0}. ", "Failed to save the results to {0} due to the following exception(s). \n\t{1}", 
			"Failed to save the results to {0} in the {1} format due to the following exception(s). \n\t{2}", 
			"Failed to save the results to {0} since {1} is one of the protected extension names. ", "Successfully saved the results to {0} in the TXT format. ", 
			"Successfully saved the results to {0} in the {1} format. ", "The results are invalid. ", "{0}"
		):
			return True
		else:
			self.__generationDiagnostics["Saver"].append("The statement {0} is not official. ".format(repr(string)))
			return False
	def __checkFunctionString(self:object, string:str, functionName:str) -> bool:
		descriptor = functionName + ": "
		descriptorLength = len(descriptor)
		if self.__collectionMode:
			if string not in Builder.__GenerationDiagnostics["Function"]:
				Builder.__GenerationDiagnostics["Function"].append(string)
			return True
		elif string in (
			"Basic: Failed to initialize the curve with name {0} due to {1}. ", "Basic: {0} failed on {1} due to {2}. ", "Curve: ({0}, {1})", "Curves: {0}", 
			"Device: Failed to parse {0} due to {1}. ", "Device: Failed to patch {0} with {1} due to {2}. ", "Device: {0} failed on {1} due to {2}. ", 
			"Is the scheme correct? {0}. ", "One: {0}", "Scheme: {0}", "Solution: {0}", "Time: {0}", "runCount: {0}"
		):
			return True
		elif not functionName:
			self.__generationDiagnostics["Function"].append("The statement {0} appears in a private function. ".format(repr(string)))
			return False
		elif not string.startswith(descriptor):
			self.__generationDiagnostics["Function"].append("The statement {0} should start with {1}. ".format(repr(string), repr(descriptor)))
			return False
		elif string[descriptorLength:] in (
			"An irregular security parameter ($\\lambda = {0}$) is specified. It is recommended to use 224, 256, 384, 512, or 1024 as the security parameter. ", (
				"Each of the variables $S_A$, $P_A$, $S_B$, and $P_B$ should be a tuple containing 4 elements of $\\mathbb{Z}_r$, "
				+ "but at least one of them is not, all of which have been generated randomly. "
			), "The securtiy parameter should be a positive integer, but it is not, which has been defaulted to {0}. ", (
				"The variables $n$ and $d$ should be two positive integers satisfying $2 \\leqslant d \\leqslant n$, but they are not, "
				+ "which have been defaulted to ${0}$ and ${1}$, respectively. "
			), (
				"The variables $n$ and $m$ should be two positive integers satisfying $1 \\leqslant m \\leqslant n$, but they are not, "
				+ "which have been defaulted to ${0}$ and ${1}$, respectively. "
			), (
				"The variables $n$, $k$, and $d$ should be three positive integers satisfying $1 \\leqslant d \\leqslant k \\leqslant n$, but they are not, "
				+ "which have been defaulted to ${0}$, ${1}$, and ${2}$, respectively. "
			), "The ``BSetup`` procedure has not been called yet. The program will call the ``BSetup`` first and finish the ``{0}`` subsequently. ".format(functionName), 
			"The ``Setup`` procedure has not been called yet. The program will call the ``Setup`` first and finish the ``{0}`` subsequently. ".format(functionName), 
			"The passed message (bytes) is too long, which has been cast. ", "The passed message (int) is too long, which has been cast. ", 
			"The securtiy parameter should be a positive integer, but it is not, which has been defaulted to {0}. ", 
			"The variable $L$ should be a list, but it is not, which has been initialized as an empty list. ", 
			"This scheme is only applicable to symmetric groups of prime orders. The curve name has been defaulted to \"SS512\". "
		) or match("^The variable \\$[ \'(),\\-0-9A-Za-z\\\\_{}]+\\$ has been generated accordingly\\. $", string[descriptorLength:]) or match((
			"^The variable \\$[ \'*,\\-0-9A-Za-z\\\\\\^_{|}]+\\$ should be a (?:set|subset of \\$[\'A-Z]+\\$|tuple( or a list)?) containing .+, but it is not, "
			+ "which has been generated (?:accordingly|randomly|randomly with (?:a length of \\$.+\\$|\\$M \\\\in \\\\mathbb{G}_T\\$ generated randomly|\\$[A-Za-z]\\$ set to .+))\\. $"
		), string[descriptorLength:]) or match(
			"^The variable \\$[*0-9A-Za-z\\\\\\^_{}]+\\$ should be (?:a ``bytes`` object|an integer), but it is not, which has been generated (?:accordingly|randomly)\\. $", 
		string[descriptorLength:]) or match((
			"^The variable \\$[*0-9A-Za-z\\\\\\^_{}]+\\$ should be an element (?:of \\$\\\\(?:mathbb\\{G\\}_(?:1|2|T)|mathbb\\{Z\\}_r)\\$|in \\$s\\$), "
			+ "but it is not, which has been generated (accordingly|randomly)\\. $"
		), string[descriptorLength:]) or match((
			"^The variable \\$[0-9A-Za-z\\\\_{}]+\\$ should be an integer or a ``bytes`` object, "
			+ "but it is not, which has been (?:defaulted to .+|generated accordingly|generated randomly)\\. $"
		), string[descriptorLength:]) or match(
			"^The variable \\$[A-Za-z\\\\_{}]+\\$ should be a positive integer( not smaller than \\$[0-9]\\$)?, but it is not, which has been defaulted to .+\\. $", 
		string[descriptorLength:]) or match((
			"^The variable \\$[\'()A-Za-z\\\\_{}]+\\$ should be a ``dict`` containing \\$[a-z]\\$ ``[a-z]+``--``[a-z]+`` pairs, "
			+ "but it is not, which has been generated (?:accordingly|randomly)\\. $"
		), string[descriptorLength:]):
			return True
		else:
			print(repr(string))
			self.__generationDiagnostics["Function"].append("The statement {0} is not official. ".format(repr(string)))
			return False
	def generate(self:object) -> None:
		if self.__flag >= 1:
			self.__flag, self.__generationDiagnostics, self.__generationTimeConsumption, self.__compilationDiagnostics, self.__compilationTimeConsumption = (
				1, {"":[], "Saver":[], "Function":[]}, None, None, None
			)
			startTime = perf_counter()
			try:
				with open(self.__schemeFilePath, "rb") as f:
					tree = parse_module(f.read())
				makedirs(self.__targetDirectoryPath, exist_ok = True)
				with open(self.__schemeLaTeXFilePath, "w", encoding = tree.encoding) as f:
					f.write("\\documentclass[a4paper]{article}\n\\setlength{\\parindent}{0pt}\n\\usepackage{amsmath,amssymb}\n\\usepackage{bm}\n\n\\begin{document}\n\n")
					stack = [tree]
					while stack:
						element = stack.pop()
						if isinstance(element, Call) and isinstance(element.func, Name) and "print" == element.func.value:
							for argument in element.args:
								string = self.__evaluateString(argument.value)
								if isinstance(string, str):
									self.__checkString(string)
						elif isinstance(element, ClassDef) and "Saver" == element.name.value:
							s, descriptor = [element], element.name.value + ": "
							while s:
								ele = s.pop()
								if isinstance(ele, Call) and isinstance(ele.func, Name) and "print" == ele.func.value:
									for argument in ele.args:
										string = self.__evaluateString(argument.value)
										if isinstance(string, str):
											self.__checkSaverString(string)
								elif isinstance(ele, CSTNode):
									s.extend(reversed(list(ele.children)))
						elif isinstance(element, ClassDef) and element.name.value.startswith("Scheme"): # match("^class\\s+Scheme[0-9A-Z_a-z]*", line)
							f.write("\\section{" + element.name.value.replace("_", "\\_") + "}\n\n")
							for item in element.body.body:
								if isinstance(item, FunctionDef):
									s, mode, functionName = [item], False, ""
									if "__init__" == item.name.value: # match("^\tdef\\s+__init__", line)
										if item.body.header.comment:
											f.write(item.body.header.comment.value.lstrip("# ") + "\n\n")
										functionName = "Init"
									elif not item.name.value.startswith("_") and "getLengthOf" != item.name.value: # match("^\tdef\\s+[A-Za-z][0-9A-Z_a-z]*", line)
										if item.body.header.comment:
											f.write("\\subsection{" + item.body.header.comment.value.lstrip("# ") + "}" + "\n\n")
										functionName = item.name.value
									while s:
										ele = s.pop()
										if isinstance(ele, (EmptyLine, TrailingWhitespace)):
											if ele.comment:
												if ele.comment.value in ("# Flag #", "# Return #", "# Scheme #"):
													if False == mode:
														mode = True
												elif mode:
													comment = ele.comment.value.lstrip("# ")
													characterIndex, commentLength = 0, len(comment)
													while characterIndex < commentLength:
														if '\\' == comment[characterIndex]:
															characterIndex += 1
															if characterIndex < commentLength:
																if comment[characterIndex] in ('(', '['):
																	if isinstance(mode, bool):
																		mode = "\\" + comment[characterIndex]
																	else:
																		raise ValueError((mode, comment, characterIndex))
																elif ')' == comment[characterIndex]:
																	if "\\(" == mode:
																		mode = True
																	else:
																		raise ValueError((mode, comment, characterIndex))
																elif ']' == comment[characterIndex]:
																	if "\\[" == mode:
																		mode = True
																	else:
																		raise ValueError((mode, comment, characterIndex))
																characterIndex += 1
															else:
																break
														elif '$' == comment[characterIndex]:
															characterIndex += 1
															dollarCount = 1
															while characterIndex < commentLength and '$' == comment[characterIndex]:
																characterIndex += 1
																dollarCount += 1
															if isinstance(mode, str):
																if "$" * dollarCount == mode:
																	mode = True
																else:
																	raise ValueError((mode, comment, characterIndex))
															else:
																mode = "$" * dollarCount
														else:
															characterIndex += 1
													f.write(comment + ("\n" if isinstance(mode, str) else "\n\n"))
										elif isinstance(ele, Call) and isinstance(ele.func, Name) and "print" == ele.func.value:
											for argument in ele.args:
												string = self.__evaluateString(argument.value)
												if isinstance(string, str):
													self.__checkFunctionString(string, functionName)
										elif isinstance(ele, CSTNode):
											s.extend(reversed(list(ele.children)))
								elif isinstance(item, CSTNode):
									stack.extend(reversed(list(item.children)))
						elif isinstance(element, CSTNode):
							stack.extend(reversed(list(element.children)))
					f.write("\\end{document}")
				self.__flag = 2
			except BaseException as e:
				self.__generationDiagnostics = e
				raise e
			endTime = perf_counter()
			self.__generationTimeConsumption = endTime - startTime
	def compile(self:object) -> None:
		if self.__flag >= 2:
			self.__flag = 2
			startTime = perf_counter()
			try:
				result = run(("pdflatex", self.__schemeLaTeXFileName), capture_output = True, text = True, timeout = Builder.__DefaultCompilationTimeout, cwd = self.__targetDirectoryPath)
				if EXIT_SUCCESS == result.returncode:
					self.__flag = 3
				else:
					self.__compilationDiagnostics = result
			except TimeoutExpired as e:
				self.__compilationDiagnostics = {"cmd":e.cmd, "stderr":e.stderr, "stdout":e.stdout, "timeout":e.timeout}
			except BaseException as e:
				self.__compilationDiagnostics = e
			endTime = perf_counter()
			self.__compilationTimeConsumption = endTime - startTime
	def getFlag(self:object) -> int:
		return self.__flag
	def getGenerationStatement(self:object) -> str:
		if self.__flag >= 2:
			if isinstance(self.__generationDiagnostics, dict) and any(self.__generationDiagnostics.values()):
				warningCount = sum(len(warnings) for warnings in self.__generationDiagnostics.values())
				return "Successfully generated the LaTeX source code {0} for {1}. The time consumption is {2:.9f} second(s). However, there {3} {4}. ".format(
					repr(self.__schemeLaTeXFilePath), repr(self.__schemeFilePath), self.__generationTimeConsumption, 
					("are {0} warnings" if warningCount > 1 else "is {0} warning").format(warningCount), self.__generationDiagnostics
				)
			else:
				return "Successfully generated the LaTeX source code {0} for {1}. The time consumption is {2:.9f} second(s). ".format(
					repr(self.__schemeLaTeXFilePath), repr(self.__schemeFilePath), self.__generationTimeConsumption
				)
		elif self.__flag >= 1:
			if self.__generationDiagnostics is None:
				return "Please call the ``generate`` method function to generate the LaTeX source code {0} for {1}. ".format(repr(self.__schemeLaTeXFilePath), repr(self.__schemeFilePath))
			else:
				return "Failed to generate the LaTeX source code {0} for {1} due to {2}. The time consumption is {3:.9f} second(s). ".format(
					repr(self.__schemeLaTeXFilePath), repr(self.__schemeFilePath), repr(self.__generationDiagnostics), self.__generationTimeConsumption
				)
		else:
			return "The file paths passed should be strings. "
	def getCompilationStatement(self:object) -> str:
		if self.__flag >= 3:
			return "Successfully compiled the LaTeX source code {0} to {1} for {2}. The time consumption is {3:.9f} second(s). ".format(
				repr(self.__schemeLaTeXFilePath), repr(self.__schemePDFFilePath), repr(self.__schemeFilePath), self.__compilationTimeConsumption
			)
		elif self.__flag >= 2:
			if self.__compilationDiagnostics is None:
				return "Please call the ``compile`` method function to compile the LaTeX source code {0} to {1} for {2}. ".format(
					repr(self.__schemeLaTeXFilePath), repr(self.__schemePDFFilePath), repr(self.__schemeFilePath)
				)
			elif isinstance(self.__compilationDiagnostics, FileNotFoundError):
				return "Failed to compile the LaTeX source code {0} to {1} for {2}. Cannot execute ``pdflatex``. ".format(
					repr(self.__schemeLaTeXFilePath), repr(self.__schemePDFFilePath), repr(self.__schemeFilePath)
				) + "Please try to install ``pdflatex`` via ``sudo apt-get install -y texlive-latex-base``. "
			else:
				return "Failed to compile the LaTeX source code {0} to {1} for {2} due to {3}. The time consumption is {4:.9f} second(s). ".format(
					repr(self.__schemeLaTeXFilePath), repr(self.__schemePDFFilePath), repr(self.__schemeFilePath), repr(self.__compilationDiagnostics), self.__compilationTimeConsumption
				)
		elif self.__flag >= 1:
			return "Please call the ``generate`` method function before the ``compile`` method function for {0}. ".format(repr(self.__schemeFilePath))
		else:
			return "The file paths passed should be strings. "
	@staticmethod
	def getGenerationDiagnostics():
		for warnings in Builder.__GenerationDiagnostics.values():
			warnings.sort()
		return Builder.__GenerationDiagnostics

class Builders: # ("%%", "%d", "%n", "%p", "%x") = ("%", "driveLetter:", "mainFileName", "/directoryPath", ".extension")
	__DefaultFormatString = Parser.getDefaultOutput()
	__DefaultSchemeFilePathPrompt = "[F] "
	__DefaultGenerationPrompt = "[G] "
	__DefaultCompilationPrompt = "[C] "
	def __init__(self:object, *paths:tuple, formatString:str = __DefaultFormatString, collectionMode:bool = False) -> object:
		self.__formatString = formatString if isinstance(formatString, str) else Builders.__DefaultFormatString
		self.__collectionMode = collectionMode is True
		self.__filePaths = []
		self.__builders = []
		self.updateFilePaths(*paths if paths else ".")
	def __format(self:object, _d:str = "", _n:str = "", _p:str = "", _x:str = ".py") -> str:
		d, n, p, x = _d if isinstance(_d, str) else "", _n if isinstance(_n, str) else "", _p if isinstance(_p, str) else "", _x if isinstance(_x, str) else ".py"
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
		originalLength, stack = len(self.__builders), list(reversed(paths))
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
									not islink(absoluteFilePath) and isfile(absoluteFilePath) and splitext(fileName)[1] == ".py"
									and fileName.startswith("Scheme") and absoluteFilePath not in self.__filePaths
								):
									filePaths.append(absoluteFilePath)
						filePaths.sort()
						self.__filePaths.extend(filePaths)
						del filePaths
					elif isfile(element):
						fileName = basename(element)
						if splitext(fileName)[1] == ".py" and fileName.startswith("Scheme"):
							absoluteFilePath = abspath(element)
							if absoluteFilePath not in self.__filePaths:
								self.__filePaths.append(absoluteFilePath)
		for filePath in self.__filePaths[originalLength:]:
			dp, nx = split(filePath)
			d, p = splitdrive(dp)
			n, x = splitext(nx)
			self.__builders.append(Builder(filePath, self.__format(_d = d, _n = n, _p = p, _x = x), collectionMode = self.__collectionMode))
		currentLength = len(self.__builders)
		return currentLength - originalLength
	def build(self:object, isSilent:bool = False) -> None:
		successCount = 0
		if not self.__collectionMode and isSilent is True:
			for builder in self.__builders:
				builder.generate()
				builder.compile()
				if builder.getFlag() >= 3:
					successCount += 1
		else:
			for filePath, builder in zip(self.__filePaths, self.__builders):
				print(Builders.__DefaultSchemeFilePathPrompt + filePath)
				builder.generate()
				print(Builders.__DefaultGenerationPrompt + builder.getGenerationStatement())
				builder.compile()
				print(Builders.__DefaultCompilationPrompt + builder.getCompilationStatement())
				if builder.getFlag() >= 3:
					successCount += 1
				print()
			if self.__collectionMode:
				print("Collected generation diagnostics {0}. ".format(Builder.getGenerationDiagnostics()))
				print()
		return successCount
	def __len__(self:object) -> int:
		return len(self.__builders)


def main() -> int:
	flag, outputPathWithoutAnExtension, decimalPlace, waitingTime, units = Parser.parse(argv)
	Parser.disableConsoleEchoes()
	if flag > EXIT_SUCCESS and flag > EOF:
		if any((
			Attribute is None, CSTNode is None, Call is None, ClassDef is None, ConcatenatedString is None, EmptyLine is None, 
			FunctionDef is None, Name is None, SimpleString is None, TrailingWhitespace is None, parse_module is None
		)):
			print("The runtime environment of the Python libcst library is not correctly configured. ")
			print("Please install the libraries via the active Python package manager (e.g., pip). ")
			errorLevel = EOF
		else:
			builders = Builders(*units, formatString = outputPathWithoutAnExtension, collectionMode = False)
			totalCount = len(builders)
			print("Gathered {0} to build. ".format(("{0} items" if totalCount > 1 else "{0} item").format(totalCount)))
			if totalCount >= 1:
				print()
				successCount = builders.build()
				errorLevel = EXIT_SUCCESS if successCount == totalCount else EXIT_FAILURE
				print("Successfully built {0} / {1} {2} with a success rate of {3:.2f}%. ".format(
					successCount, totalCount, "items" if successCount > 1 else "item", successCount * 100 / totalCount
				))
			else:
				errorLevel = EOF
				print("Nothing was built. ")
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