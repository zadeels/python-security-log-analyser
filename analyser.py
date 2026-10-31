import csv

print("SECURITY LOG ANALYSER")
print(".....................")

failed_count = 0
success_count = 0
failed_by_ip = {}
failed_threshold = 5

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
            if status not in {"SUCCESS", "FAILED"}:
                raise ValueError(f"Invalid login status '{status}' on row {row_number}")
            if not ip:
                raise ValueError(f"IP address field empty on {row_number}")
            if status == "FAILED":
                failed_count += 1
                failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

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
        if count >= failed_threshold:
            print(f"[WARNING] {ip}: {count} failed attempts (threshold: {failed_threshold})")
        else:
            print(f"[INFO] {ip}: {count} failed attempts (threshold: {failed_threshold})")
