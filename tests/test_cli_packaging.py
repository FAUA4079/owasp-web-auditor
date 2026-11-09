import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from auditor.cli import main
from auditor.__main__ import default_profile_path, load_profile

class PackagingTests(unittest.TestCase):
    def test_console_resume_uses_resume_dispatcher(self):
        for arguments in (['owasp-auditor','--resume','runs/scan-test'],
                          ['owasp-auditor','--resume=runs/scan-test']):
            with patch('sys.argv',arguments), patch('auditor.resume_engine.resume_cli') as resume, patch('auditor.__main__.main') as scan:
                main()
                resume.assert_called_once_with()
                scan.assert_not_called()
    def test_console_scan_uses_scan_dispatcher(self):
        with patch('sys.argv',['owasp-auditor','--help']), patch('auditor.__main__.main') as scan:
            main()
            scan.assert_called_once_with()
    def test_bundled_profile_loads_without_local_config(self):
        with patch('auditor.__main__.Path.is_file',return_value=False):
            profile=load_profile(default_profile_path())
        self.assertTrue(profile['verify_tls'])
        self.assertEqual(profile['max_requests'],50)
    def test_existing_local_profile_takes_precedence(self):
        with patch('auditor.__main__.Path.is_file',return_value=True):
            self.assertEqual(default_profile_path(),Path('config/public.json'))
