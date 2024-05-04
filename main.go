package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func checkWebPage(ip string, debug bool, wg *sync.WaitGroup, results chan<- string, semaphore chan struct{}) {
	defer wg.Done()
	defer func() { <-semaphore }()

	url := fmt.Sprintf("http://%s:80", ip)
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	response, err := client.Get(url)
	defer func() {
		if response != nil {
			response.Body.Close()
		}
	}()

	if err == nil {
		results <- fmt.Sprintf("%s [\033[32m✓\033[0m]", ip)
		fmt.Printf("%s [\033[32m✓\033[0m]\n", ip)
	} else {
		if debug {
			fmt.Printf("%s [\033[31mX\033[0m]\n", ip)
		}
	}
}

func scanRange(networkRange string, start, end int, debug bool, results chan<- string, maxConcurrent int) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrent)

	for i := start; i <= end; i++ {
		ip := fmt.Sprintf("%s.%d", networkRange, i)
		wg.Add(1)
		semaphore <- struct{}{}
		go checkWebPage(ip, debug, &wg, results, semaphore)
	}
	wg.Wait()
}

func getLocalIPRange() string {
	cmd := exec.Command("ifconfig")
	if _, err := exec.LookPath("ifconfig"); err != nil {
		cmd = exec.Command("ip", "addr")
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running command:", err)
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
			fields := strings.Fields(line)
			ip := fields[1]
			ip = strings.Split(ip, "/")[0]
			ipParts := strings.Split(ip, ".")
			if len(ipParts) == 4 {
				return fmt.Sprintf("%s.%s.%s", ipParts[0], ipParts[1], ipParts[2])
			}
		}
	}
	return ""
}

func runNmapOnLocalhost() {
	cmd := exec.Command("nmap", "localhost")
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

	localIPRange := getLocalIPRange()
	if localIPRange == "" {
		fmt.Println("Could not determine the local IP range.")
		return
	}

	fmt.Println("Scanning local IP range:", localIPRange)

	_, err := exec.LookPath("nmap")
	if err == nil {
		fmt.Println("Nmap found, running a port scan on localhost...")
		runNmapOnLocalhost()
	} else {
		fmt.Println("Nmap not found, skipping port scan on localhost.")
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

	scanRange(localIPRange, 1, 254, *debug, results, *maxConcurrent)

	close(results)
	wg.Wait()
}
