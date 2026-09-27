import unittest

from tcp_connection_state_parser import (
    ConnectionRecord,
    TcpState,
    parse_tcp,
    parse_tcp_file,
)


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def _row(
    sl="0",
    local="0100007F:1F90",
    remote="00000000:0000",
    state="0A",
    queue="00:00",
    timer="00:00000000",
    retrnsmt="00000000",
    uid="00000000",
    timeout="0",
    inode="0",
):
    return f"   {sl} {local} {remote} {state} {queue} {timer} {retrnsmt} {uid} {timeout} {inode}"


class TestParseTcp(unittest.TestCase):
    def test_parses_single_established_connection(self):
        lines = [HEADER, _row(local="0100007F:2328", remote="0100007F:0050", state="01")]
        records = parse_tcp(lines)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.local_address, "0100007F")
        self.assertEqual(r.local_port, 0x2328)
        self.assertEqual(r.remote_address, "0100007F")
        self.assertEqual(r.remote_port, 0x50)
        self.assertEqual(r.state, TcpState.ESTABLISHED)
        self.assertEqual(r.raw_state, 0x01)

    def test_decodes_all_known_states(self):
        for raw, expected in [
            ("01", TcpState.ESTABLISHED),
            ("02", TcpState.SYN_SENT),
            ("03", TcpState.SYN_RECV),
            ("04", TcpState.FIN_WAIT1),
            ("05", TcpState.FIN_WAIT2),
            ("06", TcpState.TIME_WAIT),
            ("07", TcpState.CLOSE),
            ("08", TcpState.CLOSE_WAIT),
            ("09", TcpState.LAST_ACK),
            ("0A", TcpState.LISTEN),
            ("0B", TcpState.CLOSING),
            ("0C", TcpState.NEW_SYN_RECV),
        ]:
            with self.subTest(raw=raw):
                records = parse_tcp([HEADER, _row(state=raw)])
                self.assertEqual(records[0].state, expected)

    def test_unknown_state_falls_back_to_close(self):
        # A value the kernel doesn't define today. We must not crash.
        records = parse_tcp([HEADER, _row(state="FF")])
        self.assertEqual(records[0].state, TcpState.CLOSE)
        self.assertEqual(records[0].raw_state, 0xFF)

    def test_decodes_timer_types(self):
        for raw_timer, expected_name in [
            ("00", "none"),
            ("01", "retransmit"),
            ("02", "keep_alive"),
            ("03", "time_wait"),
            ("04", "probe"),
        ]:
            with self.subTest(timer=raw_timer):
                records = parse_tcp([HEADER, _row(timer=f"{raw_timer}:00000010")])
                self.assertEqual(records[0].timer_type, expected_name)
                self.assertEqual(records[0].timer_expires_jiffies, 0x10)

    def test_unknown_timer_type_returns_unknown_label(self):
        records = parse_tcp([HEADER, _row(timer="09:00000005")])
        self.assertEqual(records[0].timer_type, "unknown(9)")
        self.assertEqual(records[0].timer_expires_jiffies, 5)

    def test_parses_tx_rx_queues(self):
        records = parse_tcp([HEADER, _row(queue="0010:0020")])
        self.assertEqual(records[0].tx_queue, 0x10)
        self.assertEqual(records[0].rx_queue, 0x20)

    def test_parses_uid_and_inode(self):
        records = parse_tcp([HEADER, _row(uid="000003E8", inode="12345")])
        self.assertEqual(records[0].uid, 0x3E8)
        self.assertEqual(records[0].inode, 12345)

    def test_skips_blank_lines(self):
        lines = [HEADER, "", _row(), ""]
        records = parse_tcp(lines)
        self.assertEqual(len(records), 1)

    def test_raises_on_missing_header(self):
        with self.assertRaises(ValueError):
            parse_tcp([_row()])

    def test_raises_on_empty_input(self):
        with self.assertRaises(ValueError):
            parse_tcp([])

    def test_raises_on_corrupt_row_too_few_fields(self):
        with self.assertRaises(ValueError):
            parse_tcp([HEADER, "   0 0100007F:1F90 00000000:0000 0A"])

    def test_raises_on_malformed_address_port(self):
        with self.assertRaises(ValueError):
            parse_tcp([HEADER, _row(local="0100007F")])

    def test_raises_on_malformed_queue(self):
        with self.assertRaises(ValueError):
            parse_tcp([HEADER, _row(queue="0010")])

    def test_handles_ipv6_style_address_with_colons(self):
        # IPv6 addresses in /proc/net/tcp6 contain colons, so the port split
        # must be on the LAST colon, not the first.
        lines = [HEADER, _row(local="00000000000000000000000001000000:0050")]
        records = parse_tcp(lines)
        self.assertEqual(records[0].local_address, "00000000000000000000000001000000")
        self.assertEqual(records[0].local_port, 0x50)

    def test_multiple_records_preserve_order(self):
        lines = [
            HEADER,
            _row(local="0100007F:0001"),
            _row(local="0100007F:0002"),
            _row(local="0100007F:0003"),
        ]
        records = parse_tcp(lines)
        self.assertEqual([r.local_port for r in records], [1, 2, 3])


class TestParseTcpFile(unittest.TestCase):
    def test_reads_and_parses_real_file_layout(self):
        import tempfile
        import os

        content = HEADER + "\n" + _row(local="7F000001:0050", state="0A") + "\n"
        fd, path = tempfile.mkstemp(suffix=".tcp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            records = parse_tcp_file(path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].local_address, "7F000001")
            self.assertEqual(records[0].state, TcpState.LISTEN)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
