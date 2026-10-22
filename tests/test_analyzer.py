import unittest
from analyzer import analyze

def make(ip, path, status):
    return f'{ip} - - [22/Oct/2026:10:00:00 -0300] "GET {path} HTTP/1.1" {status} 123 "-" "Lab"'

class AnalyzerTests(unittest.TestCase):
    def test_detects_repeated_auth_and_sensitive_path(self):
        rows = [make('192.0.2.10', '/login', 401) for _ in range(5)]
        rows.append(make('192.0.2.10', '/.env?secret=redacted', 404))
        result = analyze(rows)
        self.assertEqual(result['parsed_requests'], 6)
        self.assertEqual({x['category'] for x in result['findings']}, {'auth_failures', 'sensitive_paths'})

    def test_handles_malformed_lines_and_threshold(self):
        result = analyze(['garbage', make('192.0.2.1', '/', 200)], threshold=2)
        self.assertEqual(result['malformed_lines'], 1)
        self.assertEqual(result['findings'], [])

    def test_ignores_similar_path(self):
        result = analyze([make('192.0.2.1', '/administrator', 200)])
        self.assertEqual(result['findings'], [])

if __name__ == '__main__':
    unittest.main()
