package main

import (
        "bufio"
        "encoding/json"
        "flag"
        "fmt"
        "net"
        "net/http"
        "os"
        "os/signal"
        "strings"
        "sync"
        "syscall"
        "time"
)

// ANSI color codes
const (
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        GREEN  = "\033[92m"
        BLUE   = "\033[94m"
        CYAN   = "\033[96m"
        RESET  = "\033[0m"
)

var banner = fmt.Sprintf(`
%s
      _____ __              __               __  __            __
     / ___// /_  ____  ____/ /___ _____     / / / /_  ______  / /____  _____
     \__ \/ __ \/ __ \/ __  / __ '/ __ \   / /_/ / / / / __ \/ __/ _ \/ ___/
    ___/ / / / / /_/ / /_/ / /_/ / / / /  / __  / /_/ / / / / /_/  __/ /
   /____/_/ /_/\____/\__,_/\__,_/_/ /_/  /_/ /_/\__,_/_/ /_/\__/\___/_/

        +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+-+-+-+
        |S|h|o|d|a|n|h|u|n|t|e|r| |T|o|o|l| |D|e|v| |@|v|i|j|a|y|9|2|2|
        +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+-+-+-+
%s`, GREEN, RESET)


type InternetDBResponse struct {
        IP        string   `json:"ip"`
        Ports     []int    `json:"ports"`
        Vulns     []string `json:"vulns"`
        Hostnames []string `json:"hostnames"`
}

type CVEDetail struct {
        CvssV3  float64 `json:"cvss_v3"`
        Summary string  `json:"summary"`
}

var (
        showCves     bool
        showPorts    bool
        showHosts    bool
        showCvePorts bool
        concurrency  int
        ipAddr       string
        filePath     string
)

func init() {
        flag.BoolVar(&showCves, "cves", false, "Show CVEs")
        flag.BoolVar(&showPorts, "ports", false, "Show open ports")
        flag.BoolVar(&showHosts, "host", false, "Show hostnames")
        flag.BoolVar(&showCvePorts, "cve+ports", false, "Show CVEs with ports")
        flag.IntVar(&concurrency, "concurrency", 10, "Number of concurrent workers")
        flag.StringVar(&ipAddr, "ip", "", "Single IP/CIDR to scan")
        flag.StringVar(&filePath, "f", "", "File containing IPs/CIDRs")
}

func main() {
        flag.Parse()
        clearScreen()
        fmt.Println(banner)

        ips := make(chan string, 100)
        var wg sync.WaitGroup

        // Handle interrupts
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT)
        go handleInterrupt(sigChan, &wg)

        // Start workers
        for i := 0; i < concurrency; i++ {
                wg.Add(1)
                go worker(ips, &wg)
        }

        // Load IPs
        if ipAddr != "" {
                processIPOrCIDR(ipAddr, ips)
        } else if filePath != "" {
                processFile(filePath, ips)
        } else {
                fmt.Printf("%s[ERROR] No input specified%s\n", RED, RESET)
                os.Exit(1)
        }

        close(ips)
        wg.Wait()
        fmt.Printf("\n%s[INFO] Scan Completed%s\n", YELLOW, RESET)
}

func clearScreen() {
        fmt.Print("\033[H\033[2J")
}

func handleInterrupt(c <-chan os.Signal, wg *sync.WaitGroup) {
        <-c
        fmt.Printf("\n%s[INFO] Waiting for workers to finish...%s\n", YELLOW, RESET)
        wg.Wait()
        os.Exit(0)
}

func worker(ips <-chan string, wg *sync.WaitGroup) {
        defer wg.Done()
        for ip := range ips {
                processIP(ip)
                time.Sleep(time.Millisecond * 50) // Rate limiting
        }
}

func processIPOrCIDR(ip string, ips chan<- string) {
        if strings.Contains(ip, "/") {
                expandCIDR(ip, ips)
        } else {
                ips <- ip
        }
}

func expandCIDR(cidr string, ips chan<- string) {
        _, ipnet, err := net.ParseCIDR(cidr)
        if err != nil {
                fmt.Printf("%s[ERROR] Invalid CIDR: %s%s\n", RED, cidr, RESET)
                return
        }

        for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
                ips <- ip.String()
        }
}

func inc(ip net.IP) {
        for j := len(ip) - 1; j >= 0; j-- {
                ip[j]++
                if ip[j] > 0 {
                        break
                }
        }
}

func processFile(path string, ips chan<- string) {
        file, err := os.Open(path)
        if err != nil {
                fmt.Printf("%s[ERROR] %v%s\n", RED, err, RESET)
                os.Exit(1)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" {
                        processIPOrCIDR(line, ips)
                }
        }
}

func processIP(ip string) {
        url := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)
        resp, err := http.Get(url)
        if err != nil {
                fmt.Printf("%s[ERROR] Failed to fetch %s: %v%s\n", RED, ip, err, RESET)
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                fmt.Printf("%s[ERROR] %s returned %d%s\n", RED, ip, resp.StatusCode, RESET)
                return
        }

        var data InternetDBResponse
        if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
                fmt.Printf("%s[ERROR] Failed to decode response for %s: %v%s\n", RED, ip, err, RESET)
                return
        }

        logResults(ip, data)
}

func logResults(ip string, data InternetDBResponse) {
        timestamp := fmt.Sprintf("%s[INFO]%s", YELLOW, RESET)
        ipHeader := fmt.Sprintf("%s[%s]%s", BLUE, ip, RESET)

        // Determine what to show
        showAll := !(showCves || showPorts || showHosts || showCvePorts)

        // Ports
        if showPorts || showAll {
                if len(data.Ports) > 0 {
                        ports := colorJoin(data.Ports, GREEN, RESET)
                        fmt.Printf("%s %s [PORTS: %s]\n", timestamp, ipHeader, ports)
                }
        }

        // CVEs
        if showCves || showAll {
                for _, cve := range data.Vulns {
                        detail := fetchCVEDetails(cve)
                        severity := getSeverity(detail.CvssV3)
                        desc := truncate(detail.Summary, 80)
                        fmt.Printf("%s %s [%s%s%s] %s [%s%s%s]\n",
                                timestamp, ipHeader,
                                GREEN, cve, RESET,
                                severity,
                                GREEN, desc, RESET)
                }
        }

        // CVE + Ports
        if showCvePorts {
                if len(data.Vulns) > 0 && len(data.Ports) > 0 {
                        ports := colorJoin(data.Ports, GREEN, RESET)
                        for _, cve := range data.Vulns {
                                detail := fetchCVEDetails(cve)
                                severity := getSeverity(detail.CvssV3)
                                desc := truncate(detail.Summary, 80)
                                fmt.Printf("%s %s [%s%s%s] %s [%s%s%s] [PORTS: %s]\n",
                                        timestamp, ipHeader,
                                        GREEN, cve, RESET,
                                        severity,
                                        GREEN, desc, RESET,
                                        ports)
                        }
                }
        }

        // Hostnames
        if showHosts || showAll {
                if len(data.Hostnames) > 0 {
                        hosts := colorJoinString(data.Hostnames, GREEN, RESET)
                        fmt.Printf("%s %s [HOSTNAMES: %s]\n", timestamp, ipHeader, hosts)
                }
        }
}

func fetchCVEDetails(cve string) CVEDetail {
        url := fmt.Sprintf("https://cvedb.shodan.io/cve/%s", cve)
        resp, err := http.Get(url)
        if err != nil {
                return CVEDetail{}
        }
        defer resp.Body.Close()

        var detail CVEDetail
        if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
                return CVEDetail{}
        }
        return detail
}

func getSeverity(score float64) string {
        switch {
        case score >= 9.0:
                return fmt.Sprintf("%s[CRITICAL]%s", RED, RESET)
        case score >= 7.0:
                return fmt.Sprintf("%s[HIGH]%s", RED, RESET)
        case score >= 4.0:
                return fmt.Sprintf("%s[MEDIUM]%s", YELLOW, RESET)
        default:
                return fmt.Sprintf("%s[LOW]%s", GREEN, RESET)
        }
}

func colorJoin(nums []int, color, reset string) string {
        strs := make([]string, len(nums))
        for i, n := range nums {
                strs[i] = fmt.Sprintf("%s%d%s", color, n, reset)
        }
        return strings.Join(strs, ", ")
}

func colorJoinString(strs []string, color, reset string) string {
        for i := range strs {
                strs[i] = fmt.Sprintf("%s%s%s", color, strs[i], reset)
        }
        return strings.Join(strs, ", ")
}

func truncate(s string, max int) string {
        if len(s) > max {
                return s[:max] + "..."
        }
        return s
}
