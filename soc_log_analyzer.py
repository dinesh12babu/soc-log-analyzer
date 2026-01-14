from collections import Counter
from datetime import datetime

print("Advanced SOC Log Analyzer Started")

failed_ips = []
timestamps = []

# Open log file
file = open("auth.log", "r")

for line in file:
    if "Failed" in line:
        parts = line.split()
        
        # Extract IP (last word in line)
        ip = parts[-1]
        failed_ips.append(ip)
        
        # Extract timestamp (example format)
        time_str = parts[0] + " " + parts[1]
        timestamps.append(time_str)

file.close()

# Count attacks per IP
ip_counter = Counter(failed_ips)

# Detect top attacking IP
top_ip = ip_counter.most_common(1)[0]

# Time-based detection
time_counter = Counter(timestamps)

print("\n--- SOC ANALYSIS RESULT ---")
print("Total Failed Attempts:", len(failed_ips))
print("Top Attacking IP:", top_ip[0])
print("Attack Count:", top_ip[1])

# Save report to file
report = open("soc_report.txt", "w")

report.write("SOC INCIDENT REPORT\n")
report.write("-------------------\n")
report.write(f"Total Failed Attempts: {len(failed_ips)}\n")
report.write(f"Top Attacking IP: {top_ip[0]}\n")
report.write(f"Attack Count: {top_ip[1]}\n")

report.write("\nAttack Timeline:\n")

for time, count in time_counter.items():
    report.write(f"{time} --> {count} attempts\n")

report.close()

print("\nReport saved as soc_report.txt")
