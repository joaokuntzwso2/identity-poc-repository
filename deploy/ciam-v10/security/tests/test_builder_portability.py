from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[4] / 'extensions/magalu-wso2-risk/build-extension.sh'

class BuilderTests(unittest.TestCase):
    def test_no_nonportable_binary_dependencies(self):
        text = SCRIPT.read_text()
        self.assertNotIn('mapfile ', text)
        self.assertNotIn('sha256sum "$j"', text)
        self.assertNotIn('sort -z', text)
        self.assertIn('WSO2_GA_IMAGE_DIGEST', text)
        self.assertIn('javac --release 11', text)

    def test_shell_syntax(self):
        result = subprocess.run(['bash', '-n', str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()
