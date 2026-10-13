"""diff.py: сопоставление находок между прогонами и инварианты."""
import unittest

from _helpers import load_tool, make_finding

diff = load_tool("diff")


class CompareTest(unittest.TestCase):
    def check_invariants(self, old, new, result):
        s = result["summary"]
        self.assertEqual(s["same"] + s["new"], len(new))
        self.assertEqual(s["same"] + s["fixed"], len(old))

    def test_identical_runs_are_all_same(self):
        old = [make_finding(line=1), make_finding(line=2)]
        r = diff.compare(old, [dict(f) for f in old])
        self.assertEqual(r["summary"], {"new": 0, "fixed": 0, "same": 2, "moved": 0})

    def test_new_and_fixed(self):
        old = [make_finding(title="a"), make_finding(title="b")]
        new = [make_finding(title="b"), make_finding(title="c")]
        r = diff.compare(old, new)
        self.assertEqual((r["summary"]["new"], r["summary"]["fixed"], r["summary"]["same"]),
                         (1, 1, 1))
        self.check_invariants(old, new, r)

    def test_shifted_line_is_moved_not_fixed_plus_new(self):
        old = [make_finding(line=10, title="x", fid="sha1:old")]
        new = [make_finding(line=14, title="x", fid="sha1:new")]
        r = diff.compare(old, new)
        self.assertEqual(r["summary"]["moved"], 1)
        self.assertEqual((r["summary"]["new"], r["summary"]["fixed"]), (0, 0))
        self.assertEqual(r["moved"][0]["old_line"], 10)
        self.assertEqual(r["moved"][0]["new_line"], 14)
        self.check_invariants(old, new, r)

    def test_duplicates_are_matched_by_count(self):
        one = make_finding(line=1, title="dup", fid="sha1:1")
        two = make_finding(line=1, title="dup", fid="sha1:2")
        three = make_finding(line=1, title="dup", fid="sha1:3")
        r = diff.compare([one, two], [two, three, make_finding(line=1, title="dup", fid="sha1:4")])
        self.assertEqual(r["summary"]["same"], 2)
        self.assertEqual(r["summary"]["new"], 1)
        self.check_invariants([one, two], [two, three, three], r)

    def test_empty_runs(self):
        r = diff.compare([], [])
        self.assertEqual(r["summary"], {"new": 0, "fixed": 0, "same": 0, "moved": 0})


if __name__ == "__main__":
    unittest.main()
