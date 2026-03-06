import datetime
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import oschameleon
from requests.exceptions import ConnectionError
from scapy.all import IP, UDP, Raw
from oschameleon.parse_fp import get_os_pattern, split_tcp_option
from oschameleon.osfuscation import OSFuscation
from oschameleon.session.session import Session
from oschameleon.session.ext_ip import Ext_IP
from oschameleon.stack_packet.helper import drop_packet, forward_packet
from oschameleon.stack_packet.ICMP_ import send_ICMP_reply


TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "oschameleon" / "template"


class TestBasic(unittest.TestCase):
    def test_title(self):
        self.assertTrue(oschameleon.__title__ == "oschameleon")


class TestTemplateParsing(unittest.TestCase):
    def test_split_tcp_option_supports_mss_range(self):
        options, timestamp = split_tcp_option("M[54D-5BC]NW8NNS")
        self.assertIn(("NOP", 0), options)
        self.assertIn(("WScale", 8), options)
        self.assertIn(("SAckOK", ""), options)
        mss_values = [val for key, val in options if key == "MSS"]
        self.assertEqual(len(mss_values), 1)
        self.assertGreaterEqual(mss_values[0], int("54D", 16))
        self.assertLessEqual(mss_values[0], int("5BC", 16))
        self.assertEqual(timestamp, [])

    @patch("oschameleon.parse_fp.random.randint", return_value=int("580", 16))
    def test_split_tcp_option_mss_range_uses_expected_bounds(self, mock_randint):
        options, _timestamp = split_tcp_option("M[54D-5BC]NW8NNS")
        mock_randint.assert_called_once_with(int("54D", 16), int("5BC", 16))
        self.assertIn(("MSS", int("580", 16)), options)

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


class TestNFQueueCompatibility(unittest.TestCase):
    @patch("oschameleon.osfuscation.flush_tables")
    @patch("oschameleon.osfuscation.rules")
    @patch("oschameleon.osfuscation.session.get_Session")
    @patch("oschameleon.osfuscation.get_os_pattern")
    @patch("oschameleon.osfuscation.os.geteuid", return_value=0)
    @patch("oschameleon.osfuscation.NetfilterQueue")
    def test_run_fallback_without_get_socket(
        self,
        mock_nfq_cls,
        _mock_geteuid,
        _mock_get_os_pattern,
        _mock_get_session,
        _mock_rules,
        mock_flush_tables,
    ):
        # Simulate modern netfilterqueue API where get_socket/run_socket are absent.
        mock_nfq = Mock(spec=["bind", "run", "unbind"])
        mock_nfq_cls.return_value = mock_nfq

        OSFuscation.run(debug=False, template_path=str(TEMPLATE_DIR / "SIMATIC_300_PLC.txt"), server_ip="127.0.0.1")

        mock_nfq.bind.assert_called_once()
        mock_nfq.run.assert_called_once_with()
        mock_nfq.unbind.assert_called_once_with()
        self.assertGreaterEqual(mock_flush_tables.call_count, 2)


class TestICMPPython3Compatibility(unittest.TestCase):
    @patch("oschameleon.stack_packet.ICMP_.send")
    def test_udp_icmp_reply_with_cleared_payload_builds(self, _mock_send):
        class Pattern:
            TTL = 64
            UN = 0
            CL_UDP_DATA = 1
            ICMP_IPL = 56

        pkt = IP(src="192.0.2.10", dst="192.0.2.20") / UDP(sport=12345, dport=33434) / Raw(load=b"CCC")
        send_ICMP_reply(pkt, 3, Pattern(), {"DF": 0})
