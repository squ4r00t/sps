package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var mu sync.Mutex

func ScanSinglePort(host string, port int, proto string, retries int, delay_between_retries int, timeout int, open_ports *[]int, wg *sync.WaitGroup) {
	defer wg.Done()

	full_addr := host + ":" + strconv.Itoa(port)

	for i := 0; i < retries; i++ {
		conn, err := net.DialTimeout(proto, full_addr, time.Duration(timeout)*time.Millisecond)

		if err == nil {
			fmt.Printf("%d/%-7s\topen\n", port, proto)

			mu.Lock()
			*open_ports = append(*open_ports, port)
			mu.Unlock()

			conn.Close()
			return
		}

		if i < retries-1 {
			time.Sleep(time.Duration(delay_between_retries) * time.Millisecond)
		}
	}

}

func ScanAllTcpPortsForHost(host string, retries int, delay_between_retries int, timeout int, open_ports *[]int) {
	defer func() {
		fmt.Printf("Open ports on %s: ", host)
		for _, port := range *open_ports {
			fmt.Printf("%d,", port)
		}
		fmt.Println()
	}()
	// Port scanning
	wg := sync.WaitGroup{}
	for port := 1; port < 65536; port++ {
		wg.Add(1)
		go func(port int) {
			ScanSinglePort(host, port, "tcp", retries, delay_between_retries, timeout, open_ports, &wg)
		}(port)
	}
	wg.Wait()
}

func ScanCustomTcpPortsForHost(host string, ports_arr []int, retries int, delay_between_retries int, timeout int, open_ports *[]int) {
	defer func() {
		fmt.Printf("Open ports on %s: ", host)
		for _, port := range *open_ports {
			fmt.Printf("%d,", port)
		}
		fmt.Println()
	}()
	// Port scanning
	wg := sync.WaitGroup{}
	for _, port := range ports_arr {
		wg.Add(1)
		go func(port int) {
			ScanSinglePort(host, port, "tcp", retries, delay_between_retries, timeout, open_ports, &wg)
		}(port)
	}
	wg.Wait()
}

func ScanAllTcpPortsForNetwork(cidr string, retries int, delay_between_retries int, timeout int) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println("[-] Error parsing CIDR range")
		return
	}
	var open_ports []int
	for ip := ipNet.IP; ipNet.Contains(ip); inc(ip) {
		host := ip.String()

		if PingHost(host) {
			fmt.Printf("[i] Scanning %s\n", host)
			ScanAllTcpPortsForHost(host, 3, 500, 5000, &open_ports)
		}

		open_ports = nil
	}
}

func ScanCustomTcpPortsForNetwork(cidr string, ports_arr []int, retries int, delay_between_retries int, timeout int) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println("[-] Error parsing CIDR range")
		return
	}
	var open_ports []int
	for ip := ipNet.IP; ipNet.Contains(ip); inc(ip) {
		host := ip.String()

		if PingHost(host) {
			fmt.Printf("[i] Scanning %s\n", host)
			ScanCustomTcpPortsForHost(host, ports_arr, 3, 500, 5000, &open_ports)
		}

		open_ports = nil
	}
}

// Helper function to increment an IP address (used for CIDR iteration)
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// PingHost function to check if a host is reachable (live)
func PingHost(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host) // Unix-based command
	if strings.Contains(host, ":") {
		// If it's an IPv6 address, we need to handle it differently
		cmd = exec.Command("ping6", "-c", "1", "-W", "1", host)
	}
	err := cmd.Run()
	return err == nil
}
