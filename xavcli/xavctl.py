import typer
import rich
from rich.console import Console
from rich.box import SIMPLE_HEAD
from rich.table import Table
from datetime import datetime
import json
import socket
import uuid

# Typers.
main_app = typer.Typer()
on_access_app = typer.Typer()
proactive_app = typer.Typer()
main_app.add_typer(on_access_app, name="onaccess", help="On-Access Scanner Module")
main_app.add_typer(proactive_app, name="proactive", help="Proactive Protection Module")

# Console.
console = Console(highlight=False)

# Proactive protection module API.
API = "xavcore::app::proactive_protection_module_api::Api"

# Placeholder for nullable fields.
UNKNOWN = "<unknown>"

def display(value):
    """Render a nullable JSON value."""
    return UNKNOWN if value is None else str(value)

def display_time(epoch_millis):
    """Render a millisecond epoch timestamp in local time."""
    if epoch_millis is None:
        return UNKNOWN
    return datetime.fromtimestamp(epoch_millis / 1000).strftime("%Y-%m-%d %H:%M:%S")

# Columns of `proactive ps`: name -> (header, right aligned, max width, renderer).
PS_COLUMNS = {
    "pid": ("PID", True, None, lambda p: str(p["pid"])),
    "start_time": ("Start Time", False, None,
                   lambda p: display_time(p["start_time"])),
    "ppid": ("PPID", True, None, lambda p: display(p["ppid"])),
    "path": ("Path", False, 24, lambda p: display(p["exe_path"])),
    "cmdline": ("Command Line", False, 32, lambda p: display(p["cmdline"])),
    "events": ("Events", True, None, lambda p: str(p["event_count"])),
    "violations": ("Violations", True, None,
                   lambda p: str(p["violated_event_count"])),
    "score": ("Score", True, None,
              lambda p: str(round(p["severity_score"]))),
    "level": ("Level", False, None, lambda p: p["severity_level"]),
}

# Columns shown when `-c` is not given.
DEFAULT_PS_COLUMNS = "pid,ppid,path,violations,level"

# Socket connection.
def connect():
    SOCKET_PATH = "\0xavcore_proactive_protection_module_socket"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.connect(SOCKET_PATH)
    return s

def recv_reply(s):
    """Receive one reply, reassembling it if it was split over datagrams."""
    buffer = bytearray(1 * 1024 * 1024)
    length = s.recv_into(buffer)
    first = bytes(buffer[:length])

    # A reply too large for a single datagram is sent as a marker datagram
    # carrying the chunk count, followed by that many payload chunks.
    try:
        marker = json.loads(first.decode())
    except ValueError:
        return first
    if not isinstance(marker, dict) or "chunk_count" not in marker:
        return first

    chunks = []
    for _ in range(marker["chunk_count"]):
        length = s.recv_into(buffer)
        chunks.append(bytes(buffer[:length]))
    return b"".join(chunks)

def call(method: str):
    """Send one JSON-RPC request and return its result, or None on failure."""
    try:
        s = connect()
        try:
            s.send(json.dumps({
                "jsonrpc": "2.0",
                "method": f"{API}::{method}",
                "params": [],
                "id": str(uuid.uuid4()),
            }).encode())
            resp = json.loads(recv_reply(s).decode())
        finally:
            s.close()
    except socket.error as e:
        console.print(f"Socket Error: [red]{e}[/red]")
        return None

    if "error" in resp:
        console.print(f"Error: {resp['error']['code']}: {resp['error']['message']}")
        return None
    return resp["result"]

@proactive_app.command("start")
def proactive_start():
    """Start proactive protection"""
    result = call("start")
    if result is None:
        console.print(
            f"Failed to start proactive protection"
        )

@proactive_app.command("stop")
def proactive_stop():
    """Stop proactive protection"""
    result = call("stop")
    if result is None:
        console.print(
            f"Failed to stop proactive protection"
        )

@proactive_app.command("status")
def status():
    """Check proactive protection status"""
    result = call("status")
    if result is None:
        console.print(
            f"Failed to get proactive protection status"
        )
        return

    if "error" in result:
        console.print(
            f"Failed to get proactive protection status: {result["error"]["message"]} ({result["error"]["code"]})"
        )
        return

    if result["status"] == "Running":
        console.print("Status: [green]Running[/green]")
    else:
        console.print("Status: [red][bold]Stopped[/bold][/red]")
    console.print()
    console.print(f"Suspicious Process Count: [yellow]{result['suspicious_proc_count']}[/yellow]")
    console.print(f"Malicious Process Count: [red]{result['malicious_proc_count']}[/red]")
    console.print()
    console.print(f"Total Event: {result['event_count']}")
    console.print(f"Event Violates Rules: [yellow]{result['violate_rules_event_count']}[/yellow]")

@proactive_app.command("ps")
def proactive_ps(
    columns: str = typer.Option(
        DEFAULT_PS_COLUMNS,
        "-c",
        "--columns",
        help="Comma separated columns to display, e.g. pid,path,cmdline",
    ),
):
    """List the processes monitored by proactive protection"""
    names = [name.strip() for name in columns.split(",") if name.strip()]
    unknown = [name for name in names if name not in PS_COLUMNS]
    if not names or unknown:
        if unknown:
            console.print(f"Unknown column(s): {', '.join(unknown)}")
        else:
            console.print("No columns selected")
        console.print(f"Available columns: {', '.join(PS_COLUMNS)}")
        raise typer.Exit(code=1)

    result = call("processes")
    if result is None:
        console.print("Failed to list processes")
        return

    if not result:
        console.print("No processes monitored yet")
        return

    table = Table(box=SIMPLE_HEAD)
    for name in names:
        header, right, max_width, _ = PS_COLUMNS[name]
        justify = "right" if right else "left"
        if max_width is None:
            table.add_column(header, justify=justify, no_wrap=True)
        else:
            table.add_column(header, justify=justify, no_wrap=True,
                             overflow="ellipsis", max_width=max_width)

    for process in result:
        table.add_row(*[PS_COLUMNS[name][3](process) for name in names])

    # Piped output has no known width, and Rich would then squeeze this table
    # into its 80 column default. Render at a fixed width so no column is lost.
    out = console if console.is_terminal else Console(width=200, highlight=False)
    out.print(table)

if __name__ == "__main__":
    main_app()
