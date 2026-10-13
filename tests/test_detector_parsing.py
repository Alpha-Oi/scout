"""Разбор вывода внешних инструментов (не требует самих инструментов)."""
import unittest

from _helpers import load_tool

scan = load_tool("scan")

# Реальный вывод `interrogate -v -f 0 --no-color` (версия 1.7.0), имена сокращены.
INTERROGATE_OUTPUT = """\
= Coverage for /work/proj/ =
----------------------------------- Summary ------------------------------------
| Name                     |      Total |      Miss |      Cover |      Cover% |
|--------------------------|------------|-----------|------------|-------------|
| a.py                     |          4 |         4 |          0 |          0% |
| dir with space/файл.py   |          2 |         2 |          0 |          0% |
| pkg/b.py                 |          3 |         1 |          2 |         67% |
| pkg/ok.py                |          2 |         0 |          2 |        100% |
|--------------------------|------------|-----------|------------|-------------|
| TOTAL                    |         11 |         7 |          4 |       36.4% |
---------------- RESULT: PASSED (minimum: 0.0%, actual: 36.4%) -----------------
"""


class InterrogateParseTest(unittest.TestCase):
    def test_rows_are_parsed_without_header_separator_and_total(self):
        rows = scan._parse_interrogate_table(INTERROGATE_OUTPUT)
        self.assertEqual(rows, [
            ("a.py", 4, 4, 0.0),
            ("dir with space/файл.py", 2, 2, 0.0),
            ("pkg/b.py", 3, 1, 67.0),
            ("pkg/ok.py", 2, 0, 100.0),
        ])

    def test_empty_or_unrelated_output_gives_no_rows(self):
        self.assertEqual(scan._parse_interrogate_table(""), [])
        self.assertEqual(scan._parse_interrogate_table("Error: No such option '--json'"), [])

    def test_name_with_pipe_character_is_kept_whole(self):
        text = "| odd|name.py |  2 |  2 |  0 |  0% |\n"
        self.assertEqual(scan._parse_interrogate_table(text), [("odd|name.py", 2, 2, 0.0)])


if __name__ == "__main__":
    unittest.main()
