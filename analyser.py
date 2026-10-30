import csv

print("SECURITY LOG ANALYSER")
print(".....................")

failed_count = 0
success_count = 0
failed_by_ip = {}
failed_threshold = 5

with open("sample_logs/auth_log.csv", "r", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:

        if row["status"] == "FAILED":
            failed_count += 1
            ip = row["ip_address"]
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1


        elif row["status"] == "SUCCESS":
            success_count += 1

print("Total failed attempts", failed_count)
print("Total successful attempts", success_count)
print("Failed attempts per IP address:")

for ip, count in failed_by_ip.items():
    print(ip, ":", count)
    if count >= failed_threshold:
        print("[WARNING] 192.168.1.10: 5 failed attempts (threshold: 5)")
    else:
        print("[INFO] Failed attempts below detection threshold")
