# linewatch

Records internet dropouts and shows where each one started: your home network, your ISP's line, or beyond.

It pings 4 addresses once per second and writes nothing while the connection is healthy.

Works on Linux, macOS, and Windows. Needs no admin rights and nothing installed besides Python.

## 1. Get Python 3.8 or newer

| OS | How |
|---|---|
| Windows | Install from [python.org](https://www.python.org/downloads/). Use `py` in every command below. |
| macOS | Run `python3 --version` in Terminal. If it offers to install developer tools, accept. |
| Linux | Usually already installed. Check with `python3 --version`. |

## 2. Get linewatch

Download and unzip [linewatch-main.zip](https://github.com/nickinnon/linewatch/archive/refs/heads/main.zip), or run:

```
git clone https://github.com/nickinnon/linewatch
```

Open a terminal (Windows: Command Prompt) in that folder.

## 3. Test

| Linux / macOS | Windows |
|---|---|
| `python3 linewatch.py check` | `py linewatch.py check` |

It must end with `RESULT: OK`.

If it fails on Linux with `cannot open an ICMP socket`, run this and then test again:

```
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
```

## 4. Run

Use a wired connection and turn off any VPN. Otherwise the results describe the Wi-Fi or the VPN, not your line.

| | Linux / macOS | Windows |
|---|---|---|
| Run in this window (Ctrl+C stops it) | `python3 linewatch.py` | `py linewatch.py` |
| Start automatically at every login | `python3 install.py` | `py install.py` |
| Remove the automatic start | `python3 install.py --uninstall` | `py install.py --uninstall` |

Logs go to the `linewatch-logs` folder in your home folder (Windows: `C:\Users\<you>\linewatch-logs`). Uninstalling keeps them.

Options go after the command, for example: `python3 install.py --hop 203.0.113.1`

## Results

`linewatch-logs/events.log` gets one line per dropout. If it's empty or missing, there were no dropouts.

| Class | Where the fault is |
|---|---|
| `line` | Between your router and the ISP hop: your modem, the cabling, or ISP equipment |
| `upstream` | Past the ISP hop |
| `lan` | Inside your home network |
| `wan` | Past your router (shown when no ISP hop is set) |

The other files:

- `receipts/` holds one file per dropout, with every ping from 60 s before it to 30 s after.
- `summary.log` gets a line every 15 minutes with loss percentages. These lines also show the monitor was running. Each start also records how far the computer's clock is off.

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

## Tested on

- Linux: tested.
- macOS, Windows: not tested yet. If `check` fails, open an issue and paste its output.

## Tests

```
python3 -m unittest discover -s tests
```

## License

MIT
