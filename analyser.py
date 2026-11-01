import csv
from datetime import datetime, timedelta

print("SECURITY LOG ANALYSER")
print(".....................")

failed_count = 0
success_count = 0
failed_by_ip = {}
failed_threshold = 5
failed_times_by_ip = {}


file_path = input("Enter your CSV file path: ")

try:
    with open(file_path, "r", newline="") as file:
        reader = csv.DictReader(file)

        required_columns = {"timestamp", "ip_address", "username", "status"}
        actual_columns = set(reader.fieldnames or [])
        missing_columns = required_columns - actual_columns

        if len(missing_columns) > 0:
            raise ValueError(f"Missing required columns: {', '.join(sorted(missing_columns))}")
        for row_number, row in enumerate(reader, start=2):
            status = (row["status"] or "").strip()
            ip = (row["ip_address"] or "").strip()
            timestamp = (row["timestamp"] or "").strip()
            
            try:
                login_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            except ValueError:
                raise ValueError(f"Invalid timestamp '{timestamp}' on row {row_number}")

            if status not in {"SUCCESS", "FAILED"}:
                raise ValueError(f"Invalid login status '{status}' on row {row_number}")
            if not ip:
                raise ValueError(f"IP address field empty on {row_number}")
            if status == "FAILED":
                failed_count += 1
                failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

                if ip not in failed_times_by_ip:
                    failed_times_by_ip[ip] = []
                    
                failed_times_by_ip[ip].append(login_time)

            elif status == "SUCCESS":
                success_count += 1

except FileNotFoundError:
    print(f"[ERROR] File not found: {file_path}")
    print("Please check the path and try again.")

except ValueError as error:
    print(f"[ERROR] Invalid CSV format: {error}")

else:
    print("Total failed attempts", failed_count)
    print("Total successful attempts", success_count)
    print("Failed attempts per IP address:")

    for ip, count in failed_by_ip.items():
        print(f"[INFO] {ip}: {count} total failed attempts")

    for ip, times in failed_times_by_ip.items():
        times.sort()

        print(f"IP address: {ip}")
        print(f"Failed login timestamps: {len(times)}")

        if len(times) >= failed_threshold:

            for start in range(len(times) - failed_threshold + 1):

                difference = times[start + failed_threshold - 1] - times[start]

                if difference <= timedelta(minutes=5):
                    print(f"[WARNING] {ip}: {failed_threshold} failed logins within 5 minutes")
                    break