from datetime import datetime, timedelta


def generate_attack_logs():
    base_time = datetime(2026, 10, 7, 21, 20, 0)

    failed_ssh_attempts = []
    http_post_requests = []

    # Generate 3 failed SSH login attempts
    for i in range(3):
        timestamp = base_time + timedelta(seconds=i * 10)
        failed_ssh_attempts.append(
            f"{timestamp.strftime('%b %d %H:%M:%S')} server "
            f"sshd[{1300 + i}]: Failed password for testuser{i + 1} "
            f"from 203.0.113.{50 + i} port {45000 + i} ssh2\n"
        )

    # Generate 3 HTTP POST requests
    for i in range(3):
        timestamp = base_time + timedelta(seconds=30 + i * 10)
        http_post_requests.append(
            f"203.0.113.{50 + i} - - "
            f"[{timestamp.strftime('%d/%b/%Y:%H:%M:%S')} +0500] "
            f"\"POST /login HTTP/1.1\" 401 {500 + i * 20}\n"
        )

    with open("auth.log", "a") as file:
        file.writelines(failed_ssh_attempts)

    with open("access.log", "a") as file:
        file.writelines(http_post_requests)

    print("Simulation complete.")
    print(f"Added {len(failed_ssh_attempts)} failed SSH login attempts to auth.log.")
    print(f"Added {len(http_post_requests)} HTTP POST requests to access.log.")


if __name__ == "__main__":
    generate_attack_logs()
