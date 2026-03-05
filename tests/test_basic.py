import datetime
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import oschameleon
from requests.exceptions import ConnectionError
from oschameleon.parse_fp import get_os_pattern
from oschameleon.session.session import Session
from oschameleon.session.ext_ip import Ext_IP
from oschameleon.stack_packet.helper import drop_packet, forward_packet


TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "oschameleon" / "template"


class TestBasic(unittest.TestCase):
    def test_title(self):
        self.assertTrue(oschameleon.__title__ == "oschameleon")


class TestTemplateParsing(unittest.TestCase):
    def test_load_simatic(self):
        pattern = get_os_pattern(str(TEMPLATE_DIR / "SIMATIC_300_PLC.txt"), False)
        self.assertGreaterEqual(pattern.TTL, 25)
        self.assertLessEqual(pattern.TTL, 35)
        self.assertFalse(bool(pattern.PROBES_2_SEND["T2"]))

    def test_load_3com(self):
        pattern = get_os_pattern(str(TEMPLATE_DIR / "3com_superstack_3.txt"), False)
        self.assertGreaterEqual(pattern.TTL, 250)
        self.assertGreater(pattern.GCD, 0)

    def test_load_windows7(self):
        pattern = get_os_pattern(str(TEMPLATE_DIR / "windows_7_SP1.txt"), False)
        self.assertTrue(bool(pattern.PROBES_2_SEND["P1"]))

    def test_load_windows10(self):
        pattern = get_os_pattern(str(TEMPLATE_DIR / "windows_10.txt"), False)
        self.assertGreaterEqual(pattern.TTL, 123)
        self.assertLessEqual(pattern.TTL, 133)

    def test_load_ubuntu2204(self):
        pattern = get_os_pattern(str(TEMPLATE_DIR / "ubuntu_2204.txt"), False)
        self.assertGreaterEqual(pattern.TTL, 59)
        self.assertLessEqual(pattern.TTL, 69)


class TestSessionTracking(unittest.TestCase):
    def test_new_session(self):
        session = Session()
        session.my_ip = "10.0.0.1"
        session.in_session("192.0.2.10", debug=False)
        self.assertEqual(len(session.sessions), 1)
        self.assertEqual(session.sessions[0].ip, "192.0.2.10")

    def test_renew_session(self):
        session = Session()
        session.my_ip = "10.0.0.1"
        session.in_session("192.0.2.11", debug=False)
        session.sessions[0].time = datetime.datetime.now() - datetime.timedelta(seconds=1)
        old_time = session.sessions[0].time

        session.in_session("192.0.2.11", debug=False)
        self.assertEqual(len(session.sessions), 1)
        self.assertGreater(session.sessions[0].time, old_time)

    def test_session_timeout(self):
        session = Session()
        session.my_ip = "10.0.0.1"
        session.in_session("192.0.2.12", debug=False)
        session.sessions[0].time = datetime.datetime.now() - datetime.timedelta(minutes=20)

        session.in_session("192.0.2.12", debug=False)
        self.assertEqual(len(session.sessions), 1)
        self.assertGreater(session.sessions[0].time, datetime.datetime.now())


class TestExtIP(unittest.TestCase):
    @patch("oschameleon.session.ext_ip.requests.get")
    def test_valid_ip(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.text = "1.2.3.4"
        mock_get.return_value = response

        ext = Ext_IP()
        result = ext.get_ext_ip(urls=["https://api.ipify.org"])
        self.assertEqual(result, "1.2.3.4")

    @patch("oschameleon.session.ext_ip.requests.get")
    def test_invalid_ip(self, mock_get):
        bad_response = Mock()
        bad_response.status_code = 200
        bad_response.text = "not-an-ip"

        good_response = Mock()
        good_response.status_code = 200
        good_response.text = "5.6.7.8"

        mock_get.side_effect = [bad_response, good_response]

        ext = Ext_IP()
        result = ext.get_ext_ip(urls=["https://bad", "https://good"])
        self.assertEqual(result, "5.6.7.8")

    @patch("oschameleon.session.ext_ip.requests.get")
    def test_all_fail(self, mock_get):
        mock_get.side_effect = ConnectionError("network down")

        ext = Ext_IP()
        result = ext.get_ext_ip(urls=["https://one", "https://two"])
        self.assertIsNone(result)


class TestNFQueueCallbacks(unittest.TestCase):
    def test_forward_packet(self):
        packet = Mock()
        forward_packet(packet)
        packet.accept.assert_called_once_with()

    def test_drop_packet(self):
        packet = Mock()
        drop_packet(packet)
        packet.drop.assert_called_once_with()
