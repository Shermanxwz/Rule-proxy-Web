from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy.windows_core_process import CoreJob


class CoreJobTests(unittest.TestCase):
    def test_job_retains_owned_process_handle_and_closes_once(self):
        api = Mock(create_job=Mock(return_value=11), is_elevated=Mock(return_value=True))
        with patch("ruleproxy.windows_core_process._get_api", return_value=api):
            job = CoreJob(SimpleNamespace(_handle=22))
        api.is_elevated.assert_called_once()
        api.configure_job.assert_called_once_with(11, 0x2000)
        api.assign_job.assert_called_once_with(11, 22)
        job.close()
        job.close()
        api.close_handle.assert_called_once_with(11)

    def test_failed_assignment_releases_job_and_surfaces_failure(self):
        api = Mock(create_job=Mock(return_value=11), is_elevated=Mock(return_value=False))
        api.assign_job.side_effect = OSError("job assignment refused")
        with patch("ruleproxy.windows_core_process._get_api", return_value=api):
            with self.assertRaisesRegex(OSError, "assignment refused"):
                CoreJob(SimpleNamespace(_handle=22))
        api.close_handle.assert_called_once_with(11)


if __name__ == "__main__":
    unittest.main()
