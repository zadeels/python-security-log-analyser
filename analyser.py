print("SECURITY LOG ANALYSER")
print(".....................")

failed_count = 0
success_count = 0
with open ("sample_logs/auth_log.csv", "r") as file:
    for line in file:
        if "FAILED" in line:
            failed_count = failed_count + 1
        
        elif "SUCCESS" in line:
            success_count += 1

print("Total failed attempts:", failed_count)
print("Total successful attempts", success_count)