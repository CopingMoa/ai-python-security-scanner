import unittest

from scanner.rules import scan_source


def rules(source: str) -> list[str]:
    return [f.rule for f in scan_source(source)]


class RuleTests(unittest.TestCase):
    def test_eval(self):
        self.assertEqual(rules("eval(user_input)"), ["PY001"])

    def test_shell_true(self):
        self.assertEqual(rules("subprocess.run(cmd, shell=True)"), ["PY002"])

    def test_shell_false_is_clean(self):
        self.assertEqual(rules("subprocess.run(['ls', '-l'])"), [])

    def test_pickle(self):
        self.assertEqual(rules("pickle.loads(blob)"), ["PY003"])

    def test_yaml_without_loader(self):
        self.assertEqual(rules("yaml.load(data)"), ["PY004"])

    def test_yaml_with_safe_loader_is_clean(self):
        self.assertEqual(rules("yaml.load(data, Loader=yaml.SafeLoader)"), [])

    def test_hardcoded_secret(self):
        self.assertEqual(rules("API_KEY = 'abc123'"), ["PY005"])

    def test_empty_secret_is_clean(self):
        self.assertEqual(rules("password = ''"), [])

    def test_weak_hash(self):
        self.assertEqual(rules("hashlib.md5(data)"), ["PY006"])

    def test_tls_verification_disabled(self):
        self.assertEqual(rules("requests.get(url, verify=False)"), ["PY007"])


if __name__ == "__main__":
    unittest.main()
