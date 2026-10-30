import csv

print("SECURITY LOG ANALYSER")
print(".....................")

failed_count = 0
success_count = 0
failed_by_ip = {}

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
