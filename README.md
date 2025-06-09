# ⚡ py-socket-port-scanner

A **blazing fast, multithreaded TCP port scanner** written in Python, featuring a colorful CLI, hostname support, logging, and open port saving — perfect for ethical hackers and cybersecurity learners.

---

## 🚀 Features

- ✅ **Multithreaded scanning** (super fast)
- 🌍 **Supports IP and hostname input**
- 🎨 **Colorful CLI output** with `colorama`
- 📊 **Live progress bar** via `tqdm`
- 💾 **Saves open ports** to `output/open_ports.txt`
- 🧠 **Logs all results** in `output/scan_log.txt`
- 📁 Auto-creates `output/` folder
- ⏱ Shows total scan duration
- 🛡️ Full error handling (invalid IPs, timeouts, etc.)

---

## 📦 Requirements

- Python 3.8+
- Install dependencies:

```bash
pip install -r requirements.txt
```

requirements.txt should contain:

```nginx
colorama
tqdm
```

⚙️ Usage
Basic scan of localhost:

```bash
python scanner.py 127.0.0.1
```

Scan a remote host from port 20 to 100 with 1-second timeout:

```bash
python scanner.py scanme.nmap.org -s 20 -e 100 -t 1
```

🧪 Example Output

```bash
[🔍] Resolved scanme.nmap.org to 45.33.32.156
[*] Scanning 45.33.32.156 from port 20 to 100...

[+] Port 22 is OPEN
[+] Port 25 is OPEN
[+] Port 80 is OPEN

[✔] Scan completed in 1.07 seconds.
[💾] Saved open ports to output/open_ports.txt
```

📂 Output Files
| File | Description |
| ----------------------- | ----------------------------- |
| `output/open_ports.txt` | List of open ports found |
| `output/scan_log.txt` | Full scan log with timestamps |

⚠️ Legal Disclaimer

This tool is for educational and ethical testing only.
Always scan targets you own or have explicit permission to test.

Author

Built by MDautev
