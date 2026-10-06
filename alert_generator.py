import csv
import json
import re
import yaml


def load_rules(filename="rules.yaml"):
    with open(filename, "r") as file:
        data = yaml.safe_load(file)

    return data.get("rules", [])


def generate_alerts(
    csv_file="parsed_logs.csv",
    rules_file="rules.yaml",
    output_file="alerts.json"
):
    rules = load_rules(rules_file)
    alerts = []

    with open(csv_file, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            event = row.get("event", "")

            for rule in rules:
                if re.search(rule["pattern"], event):
                    description = rule["description"].format(**row)

                    alert = {
                        "timestamp": row.get("timestamp", ""),
                        "rule": rule["name"],
                        "severity": rule["severity"],
                        "description": description
                    }

                    alerts.append(alert)

    with open(output_file, "w") as file:
        json.dump(alerts, file, indent=2)

    print(f"Generated {len(alerts)} alerts.")
    print(f"Alerts saved to {output_file}")


if __name__ == "__main__":
    generate_alerts()
