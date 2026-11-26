#!/usr/bin/env python3
"""
Install linewatch so it starts automatically every time you log in.

    python3 install.py [linewatch options]   install, or reinstall with new options
    python3 install.py --uninstall           remove it (logs are kept)

On Windows, type `py` instead of `python3`.

Linux: systemd user service.  macOS: LaunchAgent.  Windows: Startup folder.
"""
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import linewatch  # noqa: E402  (same folder)

HOME = os.path.expanduser("~")
LABEL = "local.linewatch"
PLATFORM = "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux"

if PLATFORM == "windows":
    DATA = os.path.join(os.environ.get("LOCALAPPDATA", HOME), "linewatch")
    STARTUP = os.path.join(os.environ.get("APPDATA", HOME), "Microsoft", "Windows", "Start Menu",
                           "Programs", "Startup", "linewatch.cmd")
elif PLATFORM == "macos":
    DATA = os.path.join(HOME, "Library", "Application Support", "linewatch")
    PLIST = os.path.join(HOME, "Library", "LaunchAgents", LABEL + ".plist")
    MAC_LOG = os.path.join(HOME, "Library", "Logs", "linewatch.log")
else:
    DATA = os.path.join(os.environ.get("XDG_DATA_HOME", os.path.join(HOME, ".local", "share")), "linewatch")
    UNIT = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.join(HOME, ".config")),
                        "systemd", "user", "linewatch.service")
    LEGACY = os.path.join(HOME, ".local", "bin", "linewatch.py")  # from the old install.sh

SCRIPT = os.path.join(DATA, "linewatch.py")
CONFIG = os.path.join(DATA, "install.json")


def say(msg):
    print(msg, flush=True)


def fail(msg):
    sys.exit("install: " + msg)


def run(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if check and r.returncode != 0:
        fail("%s failed:\n%s" % (" ".join(cmd), (r.stderr or r.stdout).strip()))
    return r


def out_dir(args):
    out = "~/linewatch-logs"
    for i, a in enumerate(args):
        if a == "--out" and i + 1 < len(args):
            out = args[i + 1]
        elif a.startswith("--out="):
            out = a[len("--out="):]
    return os.path.abspath(os.path.expanduser(out))


def python_exe():
    exe = sys.executable
    if PLATFORM == "windows":  # pythonw.exe runs without a console window
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(w):
            return w
    return exe


def saved_config():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def stop_by_file(out):
    """Ask a running linewatch to exit (used on Windows) and wait up to 20 s."""
    if not os.path.isdir(out) or not linewatch.is_running(out):
        return
    open(os.path.join(out, linewatch.STOP_FILE), "w").close()
    for _ in range(40):
        time.sleep(0.5)
        if not linewatch.is_running(out):
            return
    fail("linewatch in %s did not stop. Close it and try again." % out)


def wait_until_running(out, seconds=20):
    for _ in range(seconds * 2):
        if linewatch.is_running(out):
            return True
        time.sleep(0.5)
    return False


# --------------------------------------------------------------------------- per-OS

def systemd_quote(a):
    return '"%s"' % a.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")


def install_linux(cmd):
    if not shutil.which("systemctl"):
        fail("systemd not found. Run linewatch in a terminal instead: python3 linewatch.py")
    os.makedirs(os.path.dirname(UNIT), exist_ok=True)
    with open(UNIT, "w", encoding="utf-8") as f:
        f.write("[Unit]\nDescription=linewatch (records internet dropouts)\n\n"
                "[Service]\nExecStart=%s\nRestart=always\nRestartSec=15\n\n"
                "[Install]\nWantedBy=default.target\n" % " ".join(systemd_quote(a) for a in cmd))
    run(["systemctl", "--user", "daemon-reload"], check=True)
    run(["systemctl", "--user", "enable", "linewatch.service"], check=True)
    run(["systemctl", "--user", "restart", "linewatch.service"], check=True)
    if os.path.exists(LEGACY):
        os.remove(LEGACY)


def uninstall_linux():
    run(["systemctl", "--user", "disable", "--now", "linewatch.service"])
    for p in (UNIT, LEGACY):
        if os.path.exists(p):
            os.remove(p)
    run(["systemctl", "--user", "daemon-reload"])


def install_macos(cmd):
    import plistlib
    uid = os.getuid()
    run(["launchctl", "bootout", "gui/%d/%s" % (uid, LABEL)])
    os.makedirs(os.path.dirname(PLIST), exist_ok=True)
    os.makedirs(os.path.dirname(MAC_LOG), exist_ok=True)
    with open(PLIST, "wb") as f:
        plistlib.dump({"Label": LABEL, "ProgramArguments": cmd, "RunAtLoad": True, "KeepAlive": True,
                       "StandardOutPath": MAC_LOG, "StandardErrorPath": MAC_LOG}, f)
    if run(["launchctl", "bootstrap", "gui/%d" % uid, PLIST]).returncode != 0:
        run(["launchctl", "load", "-w", PLIST], check=True)  # older macOS


def uninstall_macos():
    run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), LABEL)])
    if os.path.exists(PLIST):
        run(["launchctl", "unload", "-w", PLIST])
        os.remove(PLIST)


def install_windows(cmd, out):
    stop_by_file(out_dir(saved_config().get("args", [])))
    stop_by_file(out)
    os.makedirs(os.path.dirname(STARTUP), exist_ok=True)
    line = subprocess.list2cmdline(cmd).replace("%", "%%")
    with open(STARTUP, "w", encoding="utf-8") as f:
        f.write('@echo off\r\nstart "" %s\r\n' % line)
    flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(cmd, creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def uninstall_windows():
    stop_by_file(out_dir(saved_config().get("args", [])))
    if os.path.exists(STARTUP):
        os.remove(STARTUP)


# --------------------------------------------------------------------------- main

def install(args):
    say("Checking that pinging works on this machine...")
    if subprocess.run([sys.executable, os.path.join(HERE, "linewatch.py"), "check"]).returncode != 0:
        fail("the check above failed, so nothing was installed.")
    os.makedirs(DATA, exist_ok=True)
    shutil.copy2(os.path.join(HERE, "linewatch.py"), SCRIPT)
    out = out_dir(args)
    cmd = [python_exe(), "-I", SCRIPT, "run", "--out", out] + \
          [a for i, a in enumerate(args) if not (a == "--out" or a.startswith("--out=")
                                                 or (i > 0 and args[i - 1] == "--out"))]
    {"linux": lambda: install_linux(cmd), "macos": lambda: install_macos(cmd),
     "windows": lambda: install_windows(cmd, out)}[PLATFORM]()
    with open(CONFIG, "w", encoding="utf-8") as f:
        json.dump({"args": args, "command": cmd}, f, indent=2)
    if not wait_until_running(out):
        fail("installed, but linewatch did not start. Run it in a terminal to see why:\n  %s"
             % subprocess.list2cmdline(cmd[:4]))
    say("\nInstalled. linewatch is running and will start every time you log in.")
    say("Logs: %s" % out)
    say("Remove it with: %s install.py --uninstall" % ("py" if PLATFORM == "windows" else "python3"))


def uninstall():
    out = out_dir(saved_config().get("args", []))
    {"linux": uninstall_linux, "macos": uninstall_macos, "windows": uninstall_windows}[PLATFORM]()
    shutil.rmtree(DATA, ignore_errors=True)
    say("Uninstalled. Your logs are still in %s" % out)


if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
    elif argv[:1] == ["--uninstall"]:
        uninstall()
    else:
        install(argv)
