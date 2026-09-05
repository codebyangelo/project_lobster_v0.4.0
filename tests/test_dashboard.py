import unittest
import os
import sys
from unittest.mock import patch, MagicMock


# Ensure dotenv and rich don't crash the import if missing locally
try:
    import dotenv
    import rich
except ImportError:
    sys.modules['dotenv'] = type('dummy', (), {'load_dotenv': lambda: None})
    sys.modules['rich'] = MagicMock()
    sys.modules['rich.live'] = MagicMock()
    sys.modules['rich.layout'] = MagicMock()
    sys.modules['rich.panel'] = MagicMock()
    sys.modules['rich.table'] = MagicMock()
    sys.modules['rich.console'] = MagicMock()
    sys.modules['rich.syntax'] = MagicMock()
    sys.modules['rich.text'] = MagicMock()
    sys.modules['rich.box'] = MagicMock()

try:
    import google.genai
except ImportError:
    import types
    google_mod = types.ModuleType('google')
    genai_mod = types.ModuleType('genai')
    genai_mod.Client = lambda **kwargs: None
    google_mod.genai = genai_mod
    sys.modules['google'] = google_mod
    sys.modules['google.genai'] = genai_mod

import lobster.cli as dashboard

class TestDashboardReporting(unittest.TestCase):

    def test_export_report_file_io(self):
        # Setup mock packet buffer
        buffer = [
            {
                "timestamp": "2026-09-03T12:00:00Z",
                "agent_id": "test-agent",
                "type": "TestVector",
                "scan_result": {
                    "status": "BLOCK", 
                    "analysis": "Simulated malicious payload."
                }
            },
            {
                "timestamp": "2026-09-03T12:00:01Z",
                "agent_id": "test-agent",
                "scan_result": {
                    "status": "ALLOW", 
                    "analysis": "Simulated safe payload."
                }
            }
        ]
        
        dummy_console = MagicMock()
        
        # We patch builtins.open to catch the JSON write, and Console to catch HTML generation
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file, \
             patch('lobster.cli.Console') as mock_console_class:
            
            generated_filename = dashboard.export_report(buffer, dummy_console)
            
            # 1. Verify JSON Export Behavior
            # Ensure open was called with a JSON filename
            file_args = mock_file.call_args[0]
            self.assertTrue(file_args[0].startswith("scan_log_"))
            self.assertTrue(file_args[0].endswith(".json"))
            self.assertEqual(file_args[1], 'w')
            
            # Verify json.dump was called correctly (the mock_file captures the file handle operations)
            written_data = "".join(call.args[0] for call in mock_file().write.call_args_list)
            self.assertIn("Simulated malicious payload.", written_data)
            self.assertIn("BLOCK", written_data)
            
            # 2. Verify HTML Export Behavior
            self.assertTrue(generated_filename.startswith("scan_report_"))
            self.assertTrue(generated_filename.endswith(".html"))
            mock_console_class.return_value.save_html.assert_called_once_with(generated_filename)

    def test_input_listener_context_manager(self):
        # Verify the context manager properly captures and restores terminal state
        with patch('sys.stdin') as mock_stdin, \
             patch('termios.tcgetattr') as mock_tcgetattr, \
             patch('termios.tcsetattr') as mock_tcsetattr, \
             patch('tty.setcbreak') as mock_setcbreak:
            
            mock_stdin.fileno.return_value = 0
            mock_tcgetattr.return_value = 'old_terminal_settings'
            
            # Enter Context
            with dashboard.InputListener() as listener:
                mock_setcbreak.assert_called_once_with(0)
                self.assertIsNotNone(listener)
                
            # Exit Context - Verify restoration
            mock_tcsetattr.assert_called_once_with(0, dashboard.termios.TCSADRAIN, 'old_terminal_settings')

    def test_input_listener_arrow_keys(self):
        # Verify escape sequence parsing for UP and DOWN arrows
        with patch('termios.tcgetattr'), patch('tty.setcbreak'), patch('termios.tcsetattr'):
            with dashboard.InputListener() as listener:
                
                # Mock select to pretend there is input ready to read
                with patch('select.select', return_value=([sys.stdin], [], [])):
                    
                    # Test UP arrow escape sequence
                    with patch('sys.stdin.read', side_effect=['\x1b', '[A']):
                        self.assertEqual(listener.get_key(), 'UP')
                        
                    # Test DOWN arrow escape sequence
                    with patch('sys.stdin.read', side_effect=['\x1b', '[B']):
                        self.assertEqual(listener.get_key(), 'DOWN')
                        
                    # Test standard character
                    with patch('sys.stdin.read', return_value='q'):
                        self.assertEqual(listener.get_key(), 'q')
                        
                # Mock select to pretend NO input is ready
                with patch('select.select', return_value=([], [], [])):
                    self.assertIsNone(listener.get_key())


if __name__ == '__main__':
    unittest.main()
