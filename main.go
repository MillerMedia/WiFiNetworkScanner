package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

func checkWebPage(ip string, debug bool, wg *sync.WaitGroup, results chan<- string, semaphore chan struct{}) {
	defer wg.Done()
	defer func() { <-semaphore }()

	protocols := []string{"http", "https"}
	successful := false

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, ip)
		client := http.Client{
			Timeout: 10 * time.Second,
		}

		if protocol == "http" {
			// Disable redirect following for the "http" protocol
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}

		if protocol == "https" {
			// Skip TLS verification for the "https" protocol
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client.Transport = tr
		}

		response, err := client.Get(url)
		if err == nil && response.StatusCode >= 200 && response.StatusCode < 400 {
			successful = true
			results <- fmt.Sprintf("%s [\033[32m✓\033[0m] (%s)", ip, protocol)
			fmt.Printf("%s [\033[32m✓\033[0m]\n", ip)
		} else if debug {
			fmt.Printf("%s [\033[31mX\033[0m] (%s) - url: %s - error: %v\n", ip, protocol, url, err)
		}

		if response != nil {
			response.Body.Close()
		}

		if successful {
			break
		}
	}

	if !successful && debug {
		fmt.Printf("%s [\033[31mX\033[0m]\n", ip)
	}
}

func scanRange(networkRange string, start, end int, debug bool, results chan<- string, maxConcurrent int) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrent)

	for x := start; x <= end; x++ {
		for y := 1; y <= 254; y++ {
			ip := fmt.Sprintf("%s.%d.%d", networkRange, x, y)
			wg.Add(1)
			semaphore <- struct{}{}
			go checkWebPage(ip, debug, &wg, results, semaphore)
		}
	}
	wg.Wait()
}

func getLocalIPRanges() []string {
	cmd := exec.Command("ifconfig")
	if _, err := exec.LookPath("ifconfig"); err != nil {
		cmd = exec.Command("ip", "addr")
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running command:", err)
		return nil
	}

	var ranges []string
	lines := strings.Split(string(output), "\n")
	var currentInterface string

	ifaceRegex := regexp.MustCompile(`^(\S+):`)

	for _, line := range lines {
		if matches := ifaceRegex.FindStringSubmatch(line); matches != nil {
			currentInterface = matches[1]
		}

		if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			ip := fields[1]
			ipAddr := strings.Split(ip, "/")[0]
			ipParts := strings.Split(ipAddr, ".")

			if currentInterface == "tun0" || currentInterface == "docker0" || strings.HasPrefix(currentInterface, "virbr") || strings.HasPrefix(currentInterface, "veth") {
				continue
			}

			if len(ipParts) == 4 {
				ranges = append(ranges, fmt.Sprintf("%s.%s", ipParts[0], ipParts[1]))
			}
		}
	}
	return ranges
}

func runNmapOnLocalhost() {
	cmd := exec.Command("nmap", "localhost", "")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error running Nmap:", err)
	}
}

func main() {
	debug := flag.Bool("debug", false, "Enable debug output")
	maxConcurrent := flag.Int("maxconcurrent", 100, "Max concurrent requests")
	flag.Parse()

	fmt.Println("Determining local IP ranges.")
	localIPRanges := getLocalIPRanges()
	if localIPRanges == nil {
		fmt.Println("Could not determine any local IP ranges.")
		return
	}

	results := make(chan string)
	var wg sync.WaitGroup

	go func() {
		for result := range results {
			if *debug {
				fmt.Println(result)
			} else {
				if strings.Contains(result, "[✓]") {
					fmt.Println(result)
				}
			}
		}
	}()

	for _, localIPRange := range localIPRanges {
		fmt.Printf("Scanning local IP range: %s.0.0/16\n", localIPRange)
		if strings.HasSuffix(localIPRange, ".0/24") {
			scanRange(strings.TrimSuffix(localIPRange, ".0/24"), 0, 0, *debug, results, *maxConcurrent)
		} else {
			scanRange(localIPRange, 0, 255, *debug, results, *maxConcurrent)
		}
	}

	close(results)
	wg.Wait()
}
