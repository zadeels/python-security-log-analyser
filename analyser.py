
import csv
from datetime import datetime, timedelta


def is_within_time_window(difference, window_minutes):
    return difference <= timedelta(minutes=window_minutes)


def detect_suspicious_ips(failed_times_by_ip, failed_threshold, window_minutes):
    suspicious_ips = set()

    for ip, times in failed_times_by_ip.items():
        times.sort()

        if len(times) >= failed_threshold:
            for start in range(len(times) - failed_threshold + 1):
                difference = times[start + failed_threshold - 1] - times[start]

                if is_within_time_window(difference, window_minutes):
                    suspicious_ips.add(ip)

                    print(
                        f"[WARNING] {ip}: {failed_threshold} failed logins within {window_minutes} minutes"
                    )

                    break

    return suspicious_ips


def read_logs(file_path):
    failed_count = 0
    success_count = 0
    failed_by_ip = {}
    failed_times_by_ip = {}

    with open(file_path, "r", newline="") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "timestamp",
            "ip_address",
            "username",
            "status"
        }

        actual_columns = set(reader.fieldnames or [])
        missing_columns = required_columns - actual_columns

        if len(missing_columns) > 0:
            raise ValueError(
                f"Missing required columns: {', '.join(sorted(missing_columns))}"
            )

        for row_number, row in enumerate(reader, start=2):
            status = (row["status"] or "").strip()
            ip = (row["ip_address"] or "").strip()
            timestamp = (row["timestamp"] or "").strip()

            try:
                login_time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )

            except ValueError:
                raise ValueError(
                    f"Invalid timestamp '{timestamp}' on row {row_number}"
                )

            if status not in {"SUCCESS", "FAILED"}:
                raise ValueError(
                    f"Invalid login status '{status}' on row {row_number}"
                )

            if not ip:
                raise ValueError(
                    f"IP address field empty on row {row_number}"
                )

            if status == "FAILED":
                failed_count += 1

                failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

                if ip not in failed_times_by_ip:
                    failed_times_by_ip[ip] = []

                failed_times_by_ip[ip].append(login_time)

            elif status == "SUCCESS":
                success_count += 1

    return failed_count, success_count, failed_by_ip, failed_times_by_ip


def export_report(failed_by_ip, suspicious_ip, output_path):
    report_columns = [
        "ip_address",
        "failed_attempts",
        "detection_status"
    ]

    with open(output_path, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=report_columns
        )

        writer.writeheader()

        for ip, count in failed_by_ip.items():
            if ip in suspicious_ip:
                detection_status = "WARNING"
            else:
                detection_status = "NO ALERT"

            writer.writerow({
                "ip_address": ip,
                "failed_attempts": count,
                "detection_status": detection_status
            })


print("SECURITY LOG ANALYSER")
print(".....................")

failed_threshold = 5
window_minutes = 5

file_path = input("Enter your CSV file path: ")


try:
    failed_count, success_count, failed_by_ip, failed_times_by_ip = read_logs(
        file_path
    )

except FileNotFoundError:
    print(f"[ERROR] File not found: {file_path}")
    print("Please check the path and try again.")

except ValueError as error:
    print(f"[ERROR] Invalid CSV format: {error}")


else:
    print("Total failed attempts:", failed_count)
    print("Total successful attempts:", success_count)
    print("Failed attempts per IP address:")

    for ip, count in failed_by_ip.items():
        print(f"[INFO] {ip}: {count} total failed attempts")

    suspicious_ip = detect_suspicious_ips(
        failed_times_by_ip,
        failed_threshold,
        window_minutes
    )

    try:
        export_report(
            failed_by_ip,
            suspicious_ip,
            "security_report.csv"
        )

    except OSError as error:
        print(f"[ERROR] Could not save security report: {error}")

    else:
        print("Security report generated: security_report.csv")
