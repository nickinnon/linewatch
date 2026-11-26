# linewatch

Records internet dropouts and shows where each one started: your home network, your ISP's line, or beyond.

It pings 4 addresses once per second and writes nothing while the connection is healthy.

## Requirements

- Linux. macOS is untested.
- Python 3.8 or newer.
- A wired connection with any VPN turned off. Otherwise the results describe the Wi-Fi or the VPN, not your line.

Check that ping is allowed without root:

```
cat /proc/sys/net/ipv4/ping_group_range
```

If it prints `1 0`, run:

```
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
```

## Run

```
git clone https://github.com/nickinnon/linewatch
cd linewatch
python3 linewatch.py
```

Press Ctrl+C to stop. Logs go to `~/linewatch-logs/`.

## Run in the background (Linux)

This starts linewatch automatically every time you log in.

```
./install.sh
```

| To | Run |
|---|---|
| Check it's running | `systemctl --user status linewatch` |
| Watch it live | `journalctl --user -fu linewatch` |
| Stop it | `systemctl --user stop linewatch` |
| Uninstall | `systemctl --user disable --now linewatch && rm ~/.local/bin/linewatch.py ~/.config/systemd/user/linewatch.service` |

Options go after `install.sh`, for example: `./install.sh --hop 203.0.113.1`

## Results

`~/linewatch-logs/events.log` gets one line per dropout. If it's empty or missing, there were no dropouts.

| Class | Where the fault is |
|---|---|
| `line` | Between your router and the ISP hop: your modem, the cabling, or ISP equipment |
| `upstream` | Past the ISP hop |
| `lan` | Inside your home network |
| `wan` | Past your router (shown when no ISP hop is set) |

The other files:

- `receipts/` holds one file per dropout, with every ping from 60 s before it to 30 s after.
- `summary.log` gets a line every 15 minutes with loss percentages. These lines also show the monitor was running.

## Compare two homes

1. Run linewatch in both homes with the same `--hop`.
2. Copy the other home's log folder to your computer.
3. Run:

```
python3 linewatch.py compare ~/linewatch-logs ./other-home-logs
```

`MATCH` means both homes dropped within 5 seconds of each other, which points to shared wiring or equipment.

## Options

| Option | Default | What it does |
|---|---|---|
| `--out DIR` | `~/linewatch-logs` | Where logs are written |
| `--hop IP` | auto | The ISP router to ping. Auto-detect can pick a different router each run, so set it explicitly when comparing homes. Use `none` to skip it. |
| `--internet IPs` | `1.1.1.1,8.8.8.8` | Internet addresses to ping |
| `--stall-ms N` | `1000` | A reply slower than this counts as a failure |

For every option: `python3 linewatch.py --help`

## Privacy

The logs contain your router's local IP, the ISP hop's IP, and timestamps. They don't contain your public IP, MAC addresses, or hostnames.

## Tests

```
python3 -m unittest discover -s tests
```

## License

MIT
