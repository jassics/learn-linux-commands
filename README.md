# Learn Linux Commands with examples
Learn Linux Commands with examples which are useful for developers, system admin, security folks and other tech professionals.
This guide moves from foundational knowledge to specialized tools for system administration and security, emphasizing practical, real-world examples.

### The Linux Philosophy: Combining Tools

Before we dive in, remember the core philosophy of the Linux command line: **small, single-purpose tools that can be combined to perform complex tasks.** This is done primarily through:

* **Piping (`|`)**: Sends the output of one command as the input to another.
* **Redirection (`>` and `>>`)**: Sends output to a file, overwriting (`>`) or appending (`>>`).
* **Chaining (`&&` and `;`)**: Executes commands sequentially. `&&` only runs the next command if the previous one succeeds.

---

## 📦 Core & Essential Commands

These are the absolute fundamentals for navigating and interacting with a Linux system.

### `ls` - List Directory Contents
* **What it does**: Lists files and directories.
* **Examples**:
    * List contents of the current directory: `ls`
    * List with details (permissions, owner, size, date), including hidden files: `ls -la`
    * List in a human-readable format (e.g., KB, MB): `ls -lh`
    * List in a human-readale format in time based sorted, showing latest at the bottom: `ls -lrth`
    * Listing files recursively: `ls -R`

### `cd` - Change Directory
* **What it does**: Navigates between directories.
* **Examples**:
    * Go to the `/var/log` directory: `cd /var/log`
    * Go back to the previous directory: `cd -`
    * Go to your home directory: `cd` or `cd ~`
    * Go back to up level up:  `cd ..`

### `pwd` - Print Working Directory
* **What it does**: Shows the full path of your current directory.
* **Example**: `pwd`

### `cp` - Copy Files
* **What it does**: Copies files or directories.
* **Examples**:
    * Copy `source.txt` to `destination.txt`: `cp source.txt destination.txt`
    * Copy a file into another directory: `cp /home/user/app.log /var/tmp/`
    * Copy a directory and all its contents recursively: `cp -r /home/user/project /opt/backups/`

### `mv` - Move or Rename Files
* **What it does**: Moves files/directories or renames them.
* **Examples**:
    * Rename `old_name.txt` to `new_name.txt`: `mv old_name.txt new_name.txt`
    * Move `file.log` into the `logs` directory: `mv file.log logs/`

### `rm` - Remove Files
* **What it does**: Deletes files or directories. **Use with extreme caution; there is no undo!**
* **Examples**:
    * Delete a file: `rm important_file.txt`
    * Delete an empty directory: `rmdir old_directory`
    * Delete a directory and all its contents recursively and forcefully: `rm -rf /path/to/directory`

### `man` - Manual Pages
* **What it does**: Displays the user manual for most commands. The most important command for learning.
* **Example**: `man ssh`

---

## ⚙️ System Administration & Monitoring

Commands for managing system resources, processes, and services.

### `ps` - Process Status
* **What it does**: Shows a snapshot of currently running processes.
* **Examples**:
    * List all running processes in detail: `ps aux`
    * Find the process ID (PID) of `sshd`: `ps aux | grep sshd`

### `top` / `htop` - Process Viewer
* **What it does**: Provides a real-time, interactive view of system processes. `htop` is a more user-friendly version you may need to install (`sudo apt install htop`).
* **Example**: `top` (press 'q' to quit)

### `kill` - Terminate a Process
* **What it does**: Sends a signal to a process, typically to terminate it.
* **Examples**:
    * Gracefully stop a process with PID 1234: `kill 1234`
    * Forcefully stop a misbehaving process with PID 5678 (SIGKILL): `kill -9 5678`

### `df` - Disk Free
* **What it does**: Reports file system disk space usage.
* **Example**:
    * Show disk usage in a human-readable format: `df -h`

### `du` - Disk Usage
* **What it does**: Estimates file and directory space usage.
* **Examples**:
    * Show a summary of the current directory's size: `du -sh .`
    * Find the top 10 largest directories in `/var`: `du -ah /var | sort -rh | head -n 10`

### `systemctl` - Systemd Control
* **What it does**: The primary tool for managing services (daemons) on modern Linux systems.
* **Examples**:
    * Check the status of the Nginx web server: `sudo systemctl status nginx`
    * Start the SSH service: `sudo systemctl start sshd`
    * Enable a service to start on boot: `sudo systemctl enable apache2`

### `journalctl` - Query the Systemd Journal
* **What it does**: Views logs collected by `systemd`. A powerful tool for debugging.
* **Examples**:
    * Follow all system logs in real-time: `journalctl -f`
    * Show logs specifically for the `sshd` service: `journalctl -u sshd`
    * Show kernel-level log messages: `journalctl -k`

---

## 👑 Text Processing & Automation

These are the power tools for manipulating text, searching logs, and scripting. Essential for security professionals.

### `grep` - Global Regular Expression Print
* **What it does**: Searches for patterns in text.
* **Examples**:
    * Find all occurrences of "error" in `app.log`: `grep "error" app.log`
    * Search recursively for "API_KEY" in the current directory, ignoring case: `grep -ri "API_KEY" .`
    * Show lines that *do not* contain "debug" in a log stream: `tail -f /var/log/syslog | grep -v "debug"`

### `find` - Find Files
* **What it does**: Searches for files and directories based on various criteria.
* **Examples**:
    * Find all files in `/etc` ending with `.conf`: `find /etc -name "*.conf"`
    * Find all directories modified in the last 24 hours: `find / -type d -mtime -1`
    * Find all files owned by the user `www-data` and change their permissions to `644`: `find /var/www -user www-data -type f -exec chmod 644 {} \;`

### `sed` - Stream Editor
* **What it does**: Performs text transformations on an input stream.
* **Examples**:
    * Replace all instances of "development" with "production" in `config.txt`: `sed 's/development/production/g' config.txt`
    * Delete lines containing "DEBUG" from a log file: `sed '/DEBUG/d' app.log`

### `awk` - Text Processing Language
* **What it does**: A powerful pattern-scanning and processing language, great for structured data.
* **Examples**:
    * Print the first and third columns of a space-delimited file: `awk '{print $1, $3}' data.txt`
    * Show all failed SSH login attempts from an auth log: `awk '/Failed password/ {print $11}' /var/log/auth.log`

---

## 🛡️ Networking & Security

The daily toolkit for any network, system, or application security professional.

### `ip` / `ifconfig`
* **What it does**: Manages network interfaces. `ip` is the modern standard; `ifconfig` is deprecated but still common.
* **Example**:
    * Show all network interface configurations: `ip addr show` or `ifconfig -a`

### `netstat` / `ss`
* **What it does**: Shows network connections, routing tables, and interface statistics. `ss` is the modern replacement for `netstat`.
* **Example**:
    * List all listening TCP and UDP ports and the processes using them: `sudo ss -tulpn`

### `nmap` - Network Mapper
* **What it does**: An indispensable tool for network discovery and security auditing. It can find live hosts, scan for open ports, and determine services and OS versions. **Only use on networks you are authorized to scan.**
* **Examples**:
    * Perform a basic port scan on a host: `nmap 192.168.1.1`
    * Perform a stealthy SYN scan with service version detection: `sudo nmap -sS -sV scanme.nmap.org`
    * Scan for common web vulnerabilities using a script: `nmap -p 80,443 --script http-vuln* example.com`

### `tcpdump` - Dump Traffic on a Network
* **What it does**: A command-line packet analyzer. It lets you capture and inspect network traffic in real time.
* **Examples**:
    * Capture all traffic on the `eth0` interface: `sudo tcpdump -i eth0`
    * Capture traffic to or from host `1.1.1.1` on port 53 (DNS): `sudo tcpdump -i any host 1.1.1.1 and port 53`
    * Save the capture to a file for analysis in Wireshark: `sudo tcpdump -i eth0 -w capture.pcap`

### `curl` - Client for URLs
* **What it does**: A versatile tool to transfer data with URLs. Essential for testing APIs and web application security.
* **Examples**:
    * Fetch the content of a web page: `curl https://example.com`
    * View only the HTTP headers of a response: `curl -I https://example.com`
    * Send a POST request with JSON data to an API endpoint: `curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' https://api.example.com/submit`

### `dig` - Domain Information Groper
* **What it does**: A tool for querying DNS servers.
* **Examples**:
    * Find the A record (IP address) for a domain: `dig google.com`
    * Query a specific DNS server for MX (mail exchange) records: `dig @8.8.8.8 google.com MX`

---

## 🔑 Permissions & Access Control

Managing who can do what on the system.

### `chmod` - Change Mode
* **What it does**: Changes the permissions of files and directories.
* **Examples**:
    * Make a script executable for the owner: `chmod u+x my_script.sh`
    * Set permissions using numeric codes (r=4, w=2, x=1): `chmod 755 my_script.sh` (Owner: rwx, Group: r-x, Others: r-x)
    * Remove all permissions for "others": `chmod o-rwx sensitive_file.txt`

### `chown` - Change Owner
* **What it does**: Changes the user and/or group ownership of a file or directory.
* **Examples**:
    * Change the owner of a file to `www-data`: `sudo chown www-data /var/www/index.html`
    * Change the owner and group recursively for a directory: `sudo chown -R admin:admin /opt/app`

### `sudo` - Superuser Do
* **What it does**: Executes a single command with root (administrator) privileges.
* **Example**:
    * Edit a protected system configuration file: `sudo nano /etc/hosts`


---

### 🗃️ Archiving & Compression

A fundamental task for backups, transfers, and log management.

#### `tar` - Tape Archive
* **What it does**: Bundles multiple files and directories into a single archive file (`.tar`). It's often combined with a compression utility.
* **Examples**:
    * Create a gzipped archive: `tar -czvf archive-name.tar.gz /path/to/directory`
        * `c`: create
        * `z`: compress with gzip
        * `v`: verbose (show files being processed)
        * `f`: specifies the filename
    * Extract a gzipped archive: `tar -xzvf archive-name.tar.gz`
    * List the contents of an archive without extracting: `tar -tvf archive-name.tar.gz`

---

### 🕵️ File Analysis & Forensics

Crucial for security investigations, reverse engineering, and debugging.

#### `file` - Determine File Type
* **What it does**: Inspects a file's header to determine its type, rather than just relying on the extension.
* **Examples**:
    * Identify an unknown executable: `file unknown_binary`
    * Check if a file is a script or a compiled program: `file my_script`

#### `strings` - Find Printable Strings in Files
* **What it does**: Extracts human-readable text strings from binary or data files. Incredibly useful for finding clues in unknown executables.
* **Example**:
    * Look for IP addresses, URLs, or plaintext secrets in a compiled program: `strings /usr/bin/sshd | grep "OpenSSH"`

#### `diff` - Compare Files Line by Line
* **What it does**: Shows the differences between two text files. Essential for tracking changes in code or configuration.
* **Example**:
    * Compare the old and new versions of a config file: `diff httpd.conf.old httpd.conf.new`

#### `md5sum` / `sha256sum` - Calculate Hashes
* **What it does**: Computes and checks cryptographic hashes. Used to verify file integrity and ensure a downloaded file hasn't been tampered with.
* **Examples**:
    * Generate a SHA256 hash for a file: `sha256sum ubuntu-22.04.iso`
    * Verify a downloaded file against a provided hash: `sha256sum -c hashes.txt`

---

### 💻 User & Remote Session Management

Commands for managing remote access and seeing who is on the system.

#### `ssh` - Secure Shell
* **What it does**: The standard for securely connecting to and managing remote Linux servers.
* **Examples**:
    * Connect to a server as a specific user: `ssh user@remote-host.com`
    * Connect on a different port: `ssh user@remote-host.com -p 2222`
    * **Pro Tip**: Use key-based authentication instead of passwords for vastly improved security.

#### `scp` / `rsync` - Secure Copy / Remote Sync
* **What it does**: Securely copies files over an SSH connection. `scp` is simple; `rsync` is more powerful for syncing directories and can resume transfers.
* **Examples**:
    * Copy a local file to a remote server with `scp`: `scp localfile.txt user@remote-host.com:/remote/dir/`
    * Sync a local directory to a remote server with `rsync`: `rsync -avz --progress ./local-project/ user@remote-host.com:/var/www/project`

#### `who` / `w`
* **What it does**: Shows who is currently logged into the machine. `w` provides more detail, including what command each user is running.
* **Example**: `w`

#### `last`
* **What it does**: Shows a history of the last logged-in users. Very useful for a quick security audit.
* **Example**: `last`

---

### 🛠️ Advanced Tools & Command-Line Utilities

These commands enhance your ability to combine and control other programs.

#### `xargs` - Execute Command Lines from Standard Input
* **What it does**: Builds and executes commands from standard input. It's the perfect companion to `find`.
* **Example**:
    * Find all files ending in `.tmp` and delete them efficiently: `find . -name "*.tmp" -print0 | xargs -0 rm`
        * The `-print0` and `-0` flags handle filenames with spaces correctly.

#### `tee` - Read from Stdin, Write to Stdout and Files
* **What it does**: Splits the output of a command, allowing you to see it on the screen *and* save it to a file at the same time.
* **Example**:
    * Run a script and save its output to a log file without losing the live view: `./run-tests.sh | sudo tee /var/log/test-run.log`

#### `lsof` - List Open Files
* **What it does**: A powerful diagnostic tool that lists all files currently opened by processes. Since Linux treats everything as a file (including network sockets), you can use it for many things.
* **Examples**:
    * Find out which process is using port 80: `sudo lsof -i :80`
    * See all files opened by a specific process (PID 1234): `sudo lsof -p 1234`

Adding these to your tutorial will give your audience a more complete and powerful command-line toolkit.


