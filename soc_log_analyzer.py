print("SOC Log File Analyzer")

failed_count = 0
success_count = 0

file = open("auth.log", "r")

for line in file:
    if "Failed" in line:
        failed_count += 1
    else:
        success_count += 1

file.close()

print("Total Failed Logins:", failed_count)
print("Total Successful Logins:", success_count)

if failed_count >= 3:
    print("ALERT: Possible brute force attack detected")
else:
    print("Status: Normal activity")
