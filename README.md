# linewatch

A small connection monitor for intermittent outages. Typical symptoms: video calls freeze for a few seconds, games stall, pages hang, and then everything recovers before anyone can look at it.

Once per second, linewatch pings four targets:

| target | default | what a failure here means |
|---|---|---|
| `router` | your default gateway | the problem is inside your home network |
| `hop` | first public ISP router that answers ping | (used to tell the next two classes apart) |
| `cloudflare` | 1.1.1.1 | the internet is unreachable... |
| `google` | 8.8.8.8 | ...when both of these fail together |

It records nothing while the connection is healthy. When a disruption happens, it writes one line to `events.log` and `events.csv`, plus a receipt containing every ping from a minute before to 30 seconds after. It labels each event by where the disruption starts:

| class | what failed | where the fault is |
|---|---|---|
| **line** | ISP hop and internet together, router fine | modem, coax/cable plant, or ISP access network |
| **upstream** | internet only; router and ISP hop fine | past the first ISP hop |
| **lan** | router and internet together | inside the home |
| **wan** | internet only; no ISP hop configured | somewhere past your router |

A target counts as failed for a round if its reply is lost, or if it arrives later than 1 second. During many cable dropouts, packets are queued for a few seconds and then released all at once, so the late replies count as part of the outage.

Some loss is noise and never raises an event. It is only counted in the 15-minute summaries:

- **hop-only** / **router-only**: routers give low priority to pings addressed to themselves. Loss at a hop that doesn't continue to the destination isn't real loss.
- **single**: only one internet destination failed. The problem is at that destination, not your line.

## Requirements

- Python 3.8+ (standard library only). No root is needed: it uses unprivileged ICMP sockets.
- Linux: these are allowed by default on most distributions. Check with `cat /proc/sys/net/ipv4/ping_group_range`. If it prints `1 0`, run `sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'`.
- macOS: should work, but it hasn't been tested there yet.
- `tracepath` or `traceroute` (optional), for auto-detecting the ISP hop.

## Run it

```sh
python3 linewatch.py run --out ~/linewatch-logs
```

Linux, as a background service that runs whenever you're logged in:

```sh
./install.sh --out ~/linewatch-logs
journalctl --user -fu linewatch     # watch it
```

macOS: run it in a terminal tab or `tmux`. Use `caffeinate -i python3 linewatch.py run` to keep the machine from sleeping.

### Options worth knowing

- `--hop IP`: pin the ISP hop. By default it's auto-detected as the first public router on the path to 1.1.1.1 that answers ping. ISPs load-balance across parallel routers, though, so auto-detection can pick a different one on each start. **If you're comparing homes, pin the same hop everywhere.** Use `--hop none` to skip it.
- `--internet 1.1.1.1,8.8.8.8`: the internet targets. A round counts as "internet down" only if all of them fail.
- `--stall-ms 1000`, `--timeout 10`, `--interval 1`: the stall threshold, how long to wait for a reply, and the probe rate.
- `--summary-every 900`: how often to write a summary line. These lines also prove the monitor was running.

## Output

```
~/linewatch-logs/
  events.log      one line per event (human-readable)
  events.csv      the same, machine-readable (epoch + UTC + local times)
  receipts/       per-event raw data: every round's RTT per target, one minute before through 30 s after
  summary.log     start/stop, VPN warnings, and a summary every 15 minutes (loss %, noise counts)
  summary.csv     the same summaries; used as coverage by `compare`
  paths.log       the traced path at each start (documents the topology and route changes)
```

## Comparing two homes

If two homes on the same street or building see their outages at the same moments, the cause is shared infrastructure, not anyone's modem. To check:

1. Run linewatch in both homes with **the same `--hop`**, on wired machines, with NTP enabled. Check NTP with `timedatectl` on Linux.
2. Swap log folders (zip them), then run:

```sh
python3 linewatch.py compare ~/linewatch-logs ./neighbor-logs --window 5 --class line
```

Each event comes back as one of:
- **MATCH**: the other home had an event within ±5 s.
- **no match (other was monitoring)**: a real negative.
- **unknown**: the other monitor wasn't running at that time.

## Tips

- **Use a wired machine.** On Wi-Fi, events still show up, but they're classed `lan` whenever the Wi-Fi itself drops.
- **Turn off any VPN** (Cloudflare WARP, corporate VPNs), or the internet pings go through the tunnel. On Linux, linewatch warns about this in `summary.log`.
- **Suspend and resume are handled.** In-flight pings are discarded, and the first 30 s after start, resume, or a network change are ignored.
- **Privacy.** The logs contain your router's LAN address, the ISP hop's address, and timestamps. They don't contain your public IP, MAC addresses, or hostnames. The timestamps do show when the machine was on.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## License

MIT. See `LICENSE`.
