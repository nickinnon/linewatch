"""Offline tests for linewatch's classifier and event detector (no network needed).

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import linewatch as lw  # noqa: E402

TARGETS = [lw.Target("router", "192.168.0.1", "router"),
           lw.Target("hop", "203.0.113.1", "hop"),
           lw.Target("cloudflare", "1.1.1.1", "internet"),
           lw.Target("google", "8.8.8.8", "internet")]
NAMES = [t.name for t in TARGETS]
ROLES = {t.name: t.role for t in TARGETS}
OK = {"router": 0.6, "hop": 9.0, "cloudflare": 14.0, "google": 16.0}
LOST = None


def rtts(**kw):
    d = dict(OK)
    d.update(kw)
    return d


def make_rounds(spec, t0=1_800_000_000.0):
    """spec: list of rtt dicts, one per 1-second round."""
    out = []
    for i, d in enumerate(spec):
        r = lw.Round(i + 1, t0 + i, 0, NAMES)
        r.rtt.update(d)
        out.append(r)
    return out


def detect(spec, quiet=30, context=60):
    events = []
    det = lw.Detector(TARGETS, 1.0, 1000, quiet, context, events.append)
    for r in make_rounds(spec):
        det.feed(r)
    det.flush()
    return events


class Classify(unittest.TestCase):
    def c(self, **kw):
        return lw.classify(rtts(**kw), ROLES, 1000)

    def test_ok(self):
        self.assertEqual(self.c(), "ok")

    def test_line(self):
        self.assertEqual(self.c(hop=LOST, cloudflare=LOST, google=LOST), "line")

    def test_line_stall_counts_as_failure(self):
        self.assertEqual(self.c(hop=2900.0, cloudflare=2905.0, google=2910.0), "line")

    def test_upstream(self):
        self.assertEqual(self.c(cloudflare=LOST, google=LOST), "upstream")

    def test_lan(self):
        self.assertEqual(self.c(router=LOST, hop=LOST, cloudflare=LOST, google=LOST), "lan")

    def test_hop_only_is_noise(self):
        self.assertEqual(self.c(hop=LOST), "hop-only")

    def test_router_only_is_noise(self):
        self.assertEqual(self.c(router=LOST), "router-only")

    def test_single_destination_is_noise(self):
        self.assertEqual(self.c(google=LOST), "single")

    def test_mixed(self):
        self.assertEqual(self.c(hop=LOST, google=LOST), "mixed")

    def test_wan_without_hop(self):
        roles = {"router": "router", "cloudflare": "internet"}
        self.assertEqual(lw.classify({"router": 0.5, "cloudflare": None}, roles, 1000), "wan")


class Detect(unittest.TestCase):
    def test_typical_cable_dropout(self):
        # ~6.6 s of total loss, then queued replies released at once (RTTs count down).
        spec = [OK] * 70
        spec += [rtts(hop=LOST, cloudflare=LOST, google=LOST)] * 7
        spec += [rtts(hop=v, cloudflare=v + 5, google=v + 8) for v in (2850.0, 1850.0, 1090.0)]
        spec += [OK] * 60
        events = detect(spec)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e.cls, "line")
        self.assertEqual(len(e.core), 10)
        self.assertAlmostEqual(e.duration, 10.0)
        self.assertEqual(e.by_role, {"router": 0, "hop": 10, "internet": 10})
        self.assertEqual(len(e.pre), 60)

    def test_hop_only_loss_never_raises_an_event(self):
        spec = ([OK] * 20 + [rtts(hop=LOST)]) * 10
        self.assertEqual(detect(spec), [])

    def test_single_destination_loss_never_raises_an_event(self):
        spec = ([OK] * 20 + [rtts(cloudflare=LOST)]) * 10
        self.assertEqual(detect(spec), [])

    def test_noise_after_an_event_does_not_stretch_it(self):
        spec = [OK] * 5 + [rtts(hop=LOST, cloudflare=LOST, google=LOST)] * 5
        spec += [OK] * 20 + [rtts(google=LOST)] + [OK] * 40
        events = detect(spec)
        self.assertEqual(len(events), 1)
        self.assertAlmostEqual(events[0].duration, 5.0)

    def test_close_events_merge_far_events_split(self):
        bad = [rtts(hop=LOST, cloudflare=LOST, google=LOST)] * 5
        merged = detect([OK] * 5 + bad + [OK] * 10 + bad + [OK] * 40)
        split = detect([OK] * 5 + bad + [OK] * 71 + bad + [OK] * 40)
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(split), 2)

    def test_settle_rounds_are_ignored(self):
        events = []
        det = lw.Detector(TARGETS, 1.0, 1000, 30, 60, events.append)
        for r in make_rounds([rtts(router=LOST, hop=LOST, cloudflare=LOST, google=LOST)] * 10):
            r.settle = True
            det.feed(r)
        det.flush()
        self.assertEqual(events, [])


TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.0.1                                           0.555ms
 2:  172.29.152.1                                         12.600ms
 3:  72.129.27.226                                        11.081ms
 4:  72.129.19.122                                        12.038ms asymm  7
     Too many hops: pmtu 1500
"""
TRACEROUTE = """traceroute to 1.1.1.1 (1.1.1.1), 8 hops max, 52 byte packets
 1  192.168.0.1  1.234 ms
 2  *
 3  72.129.27.226  11.081 ms
"""
TRACERT = """
Tracing route to 1.1.1.1 over a maximum of 8 hops

  1    <1 ms    <1 ms    <1 ms  192.168.0.1
  2     9 ms     8 ms    10 ms  172.29.152.1
  3     *        *        *     Request timed out.
  4    11 ms    12 ms    11 ms  72.129.27.226
"""
ROUTE_PRINT = """===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      10.8.0.1       10.8.0.5     50
          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.208     25
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.0.1  Default
"""


class Discovery(unittest.TestCase):
    def test_tracepath(self):
        self.assertEqual(lw.path_ips(TRACEPATH), ["192.168.0.1", "172.29.152.1", "72.129.27.226", "72.129.19.122"])

    def test_traceroute(self):
        self.assertEqual(lw.path_ips(TRACEROUTE), ["192.168.0.1", "72.129.27.226"])

    def test_tracert(self):
        self.assertEqual(lw.path_ips(TRACERT), ["192.168.0.1", "172.29.152.1", "72.129.27.226"])

    def test_route_print_picks_lowest_metric(self):
        self.assertEqual(lw.parse_route_print(ROUTE_PRINT), "192.168.0.1")

    def test_route_print_empty(self):
        self.assertIsNone(lw.parse_route_print(""))


class Locking(unittest.TestCase):
    def test_second_instance_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            first = lw.lock_file(d)
            self.assertIsNotNone(first)
            self.assertIsNone(lw.lock_file(d))
            self.assertTrue(lw.is_running(d))
            lw.unlock_file(first)
            self.assertFalse(lw.is_running(d))


class Outputs(unittest.TestCase):
    def test_event_files_are_written(self):
        spec = [OK] * 10 + [rtts(hop=LOST, cloudflare=LOST, google=LOST)] * 3 + [OK] * 40
        e = detect(spec)[0]

        class Args:
            interval, timeout, stall_ms = 1.0, 10.0, 1000

        with tempfile.TemporaryDirectory() as d:
            out = lw.Output(d)
            lw.write_event(out, e, TARGETS, Args)
            with open(os.path.join(d, "events.csv")) as f:
                rows = f.read().splitlines()
            self.assertEqual(rows[0].split(",")[:2], ["start_epoch", "end_epoch"])
            self.assertIn(",line,", rows[1])
            receipts = os.listdir(os.path.join(d, "receipts"))
            self.assertEqual(len(receipts), 1)
            with open(os.path.join(d, "receipts", receipts[0])) as f:
                body = f.read()
            self.assertEqual(body.count("\n>> "), 3)


if __name__ == "__main__":
    unittest.main()
