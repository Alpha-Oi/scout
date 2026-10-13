"""doctor.py: статус детектора должен совпадать с тем, как его запускает scan.py."""
import unittest
from unittest import mock

from _helpers import load_tool

doctor = load_tool("doctor")


class DoctorTest(unittest.TestCase):
    def status(self, label, which_result, module_found):
        row = next(r for r in doctor.DETECTORS if r[0] == label)
        _, command, module, spec, required = row
        with mock.patch.object(doctor.shutil, "which", return_value=which_result), \
                mock.patch.object(doctor, "module_ok", return_value=module_found):
            return doctor.check(label, command, module, spec, required)[0]

    def test_pytest_in_path_but_not_importable_is_missing(self):
        # Регрессия: pytest как uv-tool есть в PATH, но `python -m pytest`
        # тем же интерпретатором не работает, и детектор молча давал 0 находок.
        self.assertEqual(self.status("pytest-failed", "/somewhere/bin/pytest", False), "missing")

    def test_pytest_importable_is_ok(self):
        self.assertEqual(self.status("pytest-failed", None, True), "ok")

    def test_tool_in_path_is_ok_for_standalone_tools(self):
        self.assertEqual(self.status("ruff", "/usr/bin/ruff", False), "ok")

    def test_missing_everywhere_is_missing(self):
        self.assertEqual(self.status("bandit", None, False), "missing")

    def test_builtin_detectors_need_nothing(self):
        self.assertEqual(self.status("secrets", None, False), "built-in")
        self.assertEqual(self.status("todo-fixme", None, False), "built-in")

    def test_every_detector_of_scan_is_known_to_doctor(self):
        names = {r[0] for r in doctor.DETECTORS}
        scan = load_tool("scan")
        scan_names = {name for name, _fn in scan.DETECTORS}
        self.assertEqual(names, scan_names)


if __name__ == "__main__":
    unittest.main()
