from csv import writer
from os import makedirs
from os.path import join
from shutil import which
from subprocess import PIPE, STDOUT, run
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from zipfile import ZipFile

from analyze import Analyzer


class AnalyzerTests(TestCase):
	def test_archive_contains_main_tex_with_optimal_values_and_figures(self:object) -> None:
		with TemporaryDirectory() as directory:
			inputFilePath = join(directory, "results.csv")
			outputFilePath = join(directory, "figures.zip")
			with open(inputFilePath, "w", newline = "", encoding = "utf-8") as f:
				csvWriter = writer(f)
				csvWriter.writerow((
					"scheme", "curveName", "secparam", "n", "k", "d", "solution", "runCount", "correctness", "Setup(s)", "mpk(B)"
				))
				csvWriter.writerows((
					("Scheme_1", "Curve&1", 128, 15, 10, 5, "Method_A", 10, 10, 0.2, 10),
					("Scheme_1", "Curve&1", 128, 15, 10, 5, "Method&B", 10, 10, 0.1, 10),
					("Scheme_1", "Curve&1", 128, 16, 10, 5, "Method_A", 10, 10, 0.3, 20),
					("Scheme_1", "Curve&1", 128, 16, 10, 5, "Method&B", 10, 10, "", 15),
					("Scheme_1", "Curve&1", 128, 15, 10, 5, "Invalid", 10, 9, 0.01, 1),
				))
			result = Analyzer(inputFilePath, outputFilePath).analyze()
			self.assertIs(result, True)
			with ZipFile(outputFilePath, "r") as archive:
				fileNames = set(archive.namelist())
				mainTEX = archive.read("main.tex").decode("utf-8")
				pdfFileNames = tuple(sorted(fileName for fileName in fileNames if fileName.endswith(".pdf")))
			self.assertIn("main.tex", fileNames)
			self.assertIn("x2y9c3c4c5g0.pdf", fileNames)
			self.assertIn("x3y10c2c4c5g0.pdf", fileNames)
			self.assertNotIn("Invalid", mainTEX)
			self.assertIn("Scheme\\_\\allowbreak{}1", mainTEX)
			self.assertIn("Curve\\&1", mainTEX)
			self.assertIn("Method\\&B", mainTEX)
			self.assertIn("Method\\_\\allowbreak{}A", mainTEX)
			self.assertIn("\\textbf{0.1}", mainTEX)
			self.assertEqual(2, mainTEX.count("\\textbf{10}"))
			self.assertIn("\\textbf{0.3}", mainTEX)
			self.assertIn("\\textbf{15}", mainTEX)
			self.assertNotIn("\\textbf{nan}", mainTEX)
			self.assertIn("\\includegraphics[width=\\linewidth]{x2y9c3c4c5g0.pdf}", mainTEX)
			self.assertIn(
				"\\caption{The 0 group of the mapping from secparam to Setup(s) with n, k, and d fixed.}",
				mainTEX,
			)
			self.assertIn(
				"\\caption{The 0 group of the mapping from n to mpk(B) with secparam, k, and d fixed.}",
				mainTEX,
			)
			self.assertIn("\\begin{document}", mainTEX)
			self.assertIn("\\end{document}", mainTEX)
			self.assertIn("Bold metric values are optimal", mainTEX)
			self.assertIn("\\newpage\n\\section*{Figures}", mainTEX)
			self.assertEqual(len(pdfFileNames), mainTEX.count("\\begin{figure}[htbp]"))
			self.assertNotIn("The generated mapping figure.", mainTEX)
			for pdfFileName in pdfFileNames:
				self.assertIn("\\includegraphics[width=\\linewidth]{{{0}}}".format(pdfFileName), mainTEX)
			if which("pdflatex") is not None:
				texDirectory = join(directory, "tex")
				makedirs(texDirectory)
				with ZipFile(outputFilePath, "r") as archive:
					archive.extractall(texDirectory)
				compilation = run(
					("pdflatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"),
					cwd = texDirectory,
					stdout = PIPE,
					stderr = STDOUT,
					text = True,
					check = False,
				)
				self.assertEqual(0, compilation.returncode, compilation.stdout)


if "__main__" == __name__:
	main()