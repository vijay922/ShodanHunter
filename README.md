# ShodanHunter

ShodanHunter is a powerful reconnaissance tool that leverages [Shodan's InternetDB API](https://internetdb.shodan.io/) to scan and retrieve open ports, hostnames, and known vulnerabilities (CVEs) for given IP addresses or CIDR ranges.

## Features
- Scan a single IP or a list of IPs from a file
- Expand and scan CIDR ranges
- Fetch open ports from Shodan's database
- Retrieve CVEs associated with scanned IPs
- Display hostnames (if available)
- Multi-threaded scanning with configurable concurrency
- Graceful handling of interruptions (Ctrl+C)
- Color-coded output for better readability

## Installation
```sh
# Clone the repository
git clone https://github.com/vijay922/ShodanHunter.git
cd ShodanHunter

# Build the executable
go build -o ShodanHunter.go
mv ShodanHunter /usr/local/bin
```

## Usage
```sh
shodanhunter -ip <IP/CIDR> [OPTIONS]
shodanhunter -f <file> [OPTIONS]
```

### Options:
```
  -ip <IP/CIDR>         Scan a single IP or CIDR range
  -f <file>             Read IPs/CIDRs from a file
  -ports                Show open ports
  -cves                 Show associated CVEs
  -host                 Show hostnames
  -cve+ports            Show CVEs along with open ports
  -concurrency <N>      Number of concurrent workers (default: 10)
```

## Example Usage
```sh
# Scan a single IP for open ports and CVEs
./shodanhunter -ip 8.8.8.8 -ports -cves

# Scan a CIDR range and display hostnames
./shodanhunter -ip 192.168.1.0/24 -host

# Scan multiple IPs from a file with 20 concurrent workers
./shodanhunter -f targets.txt -concurrency 20
```

## How It Works
1. The script takes an IP, CIDR range, or a file containing multiple IPs.
2. It queries the [Shodan InternetDB API](https://internetdb.shodan.io/) to retrieve open ports, vulnerabilities, and hostnames.
3. The results are color-coded and displayed on the terminal.
4. If CVE details are requested, the script fetches descriptions from [Shodan's CVE database](https://cvedb.shodan.io/).
5. The program gracefully handles interrupts, ensuring workers complete their tasks before exiting.

## Dependencies
- Go (>= 1.16)
- Internet access to query the Shodan API

## License
This project is licensed under the MIT License.

## Author
Developed by Vijay Kumar (@vijay922).

