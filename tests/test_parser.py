import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import parse_auth_line


def test_parse_known_auth_log_line():
    line = (
        "Oct 04 09:15:22 server sshd[1201]: "
        "Accepted password for owais from 192.168.1.105 port 51422 ssh2"
    )

    result = parse_auth_line(line)

    assert result == {
        "timestamp": "Oct 04 09:15:22",
        "ip": "192.168.1.105",
        "event": "Accepted",
        "user": "owais",
    }
