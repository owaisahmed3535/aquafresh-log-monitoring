import csv
import re


AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) "
    r"\w+ sshd\[\d+\]: "
    r"(?P<event>Accepted|Failed) password for "
    r"(?P<user>\S+) from (?P<ip>\S+)"
)

ACCESS_PATTERN = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ "
    r"\[(?P<timestamp>[^\]]+)\] "
    r"\"(?P<event>GET|POST) (?P<path>\S+) HTTP/\d\.\d\""
)


def parse_auth_line(line):
    match = AUTH_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    return {
        "timestamp": data["timestamp"],
        "ip": data["ip"],
        "event": data["event"],
        "user": data["user"],
    }


def parse_access_line(line):
    match = ACCESS_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    return {
        "timestamp": data["timestamp"],
        "ip": data["ip"],
        "event": data["event"],
        "user": "-",
    }


def parse_logs():
    parsed_entries = []

    with open("auth.log", "r") as file:
        for line in file:
            entry = parse_auth_line(line)

            if entry:
                parsed_entries.append(entry)

    with open("access.log", "r") as file:
        for line in file:
            entry = parse_access_line(line)

            if entry:
                parsed_entries.append(entry)

    return parsed_entries


def write_csv(entries):
    with open("parsed_logs.csv", "w", newline="") as file:
        fieldnames = ["timestamp", "ip", "event", "user"]

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(entries)


if __name__ == "__main__":
    entries = parse_logs()
    write_csv(entries)

    print(f"Parsed {len(entries)} log entries.")
    print("Output saved to parsed_logs.csv")
