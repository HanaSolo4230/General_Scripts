import re
from collections import defaultdict

def parse_log(log_file):
    ip_counts = defaultdict(int)
    url_counts = defaultdict(int)
    status_counts = defaultdict(int)
    method_counts = defaultdict(int)

    # Example Apache log pattern (adjust if your log format differs)
    pattern = r'(?P<ip>\S+) - - \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<url>\S+) .+?" (?P<status>\d{3})'

    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(pattern, line)
            if match:
                ip = match.group('ip')
                url = match.group('url')
                status = match.group('status')
                method = match.group('method')

                ip_counts[ip] += 1
                url_counts[url] += 1
                status_counts[status] += 1
                method_counts[method] += 1

    # Print results
    print("Top 5 IPs:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count}")

    print("\nAll 404 errors:")
    for line in open(log_file, 'r'):
        if '404' in line:
            print(line.strip())

    print("\nTop 10 most requested URLs:")
    for url, count in sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{url}: {count}")

    print("\nAll 500 errors:")
    for line in open(log_file, 'r'):
        if '500' in line:
            print(line.strip())

    print("\nCount of requests per HTTP method:")
    for method, count in sorted(method_counts.items()):
        print(f"{method}: {count}")

# Run the script
parse_log('access_wireshark.log')