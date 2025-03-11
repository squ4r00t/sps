# SPS (SimplePortScanner)

SPS is a simple and fast TCP port scanner, with the addition that you have the possibility to run it on any server where you can authenticate via ssh without touching disk (fileless). The process works as follows:

- Authentication via SSH with the provided credentials
- Depending on the OS, a command will be executed to retrieve & execute the binary
- After the scan, results are printed on STDOUT

This can speed up scan times when we have to go through multiple pivots.

## Installation / Setup

Clone the repository:

```bash
git clone https://github.com/squ4r00t/sps
```

Compile the code for your machine:

```bash
cd sps/
go build -o sps .
```

You now have an executable that you can run on your machine. 

> You can test that it works by running it (without any arguments, it will scan all tcp ports on `127.0.0.1`).

Now, you will need to compile the code for the host that will run the `sps`. You can do it as follows:

```bash
# For linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o serve/sps
cat serve/sps | base64 -w0 | tee serve/sps.b64

# For windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o serve/sps.exe
```

Now you have all you need to get started.

## Usage

```bash
> sps --help

Usage of ./sps:
  -delay-between-retries int
        Time delay between each retry (default 500)
  -from string
        The host to run the scan from. You should also provide a ssh user and password/key
  -host string
        The host to scan, or valid CIDR range (default "127.0.0.1")
  -nmap string
        Arguments passed to nmap. Example: "-A -oN nmap" (default "no")
  -pivot-os string
        OS of the host running the scan (default "linux")
  -port string
        Ports to scan: coma-separated list or 'alltcp' for all tcp ports (default "alltcp")
  -retries int
        The number of retries before moving to another port (default 3)
  -serve-ip string
        The IP of the web server. Should be accessible by the host running the scan
  -serve-port string
        The port of the web server
  -share-name string
        The name of the share hosting the executable
  -ssh-key string
        The path to the private key file used to log in
  -ssh-pass string
        The ssh password used to log in
  -ssh-port string
        The Port ssh is running on. Default 22 (default "22")
  -ssh-user string
        The user to log in as. Should be used with -from
  -timeout int
        Time to wait for server response (default 5000)
```

### Normal Scan

```bash
# Scanning all tcp ports on a host
sps 
```

### Scanning from another machine

First, you'll need to setup either a webserver or a smbshare depending on the os of the machine:

```bash
# Python web server
cd sps/serve
python3 -m http.server 1337

# SMB share
impacket-smbserver myshare sps/serve/
```

Similar usage as a normal scan, but you'll need to provide additional arguments:
- `-from`: IP address of the machine to run scan from
- `-ssh-user`: User to authenticated as via ssh
- `-ssh-pass` or `-ssh-key`: SSH password or path to private key file (not both)
- `pivot-os`: The operating system of the machine running the scan: windows or linux (if not specified will default to linux)
- `-serve-ip` and `-serve-port`: The IP address and the port number hosting the binary (you will need to setup a web server for linux or smbshare for windows)
- `-share-name`: Name of the smb share hosting the executable (if `pivot-os` is windows)