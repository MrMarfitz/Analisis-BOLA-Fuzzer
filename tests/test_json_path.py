import unittest

from bola_fuzzer.json_path import extract_json_path


class JsonPathTest(unittest.TestCase):
    def test_extracts_nested_object_value(self):
        self.assertEqual(extract_json_path({"data": {"token": "abc"}}, "$.data.token"), "abc")

    def test_extracts_list_value(self):
        self.assertEqual(extract_json_path([{"id": 42}], "$[0].id"), 42)


if __name__ == "__main__":
    unittest.main()
