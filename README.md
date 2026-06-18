# Windows DHCP Tool

A simple, easy-to-use Windows DHCP server assignment tool. Just double-click and run.

## Features

- **Network Adapter Selection** — Automatically enumerates all local network adapters
- **IP Pool Configuration** — Set start IP, end IP, subnet mask, gateway, DNS, lease time
- **One-Click Start/Stop** — Click "Start DHCP" to run instantly, stop anytime
- **Firewall Auto-Configuration** — Automatically adds Windows firewall inbound rules (UDP 67/68) on startup, with real-time status indicator in the status bar
- **Client List** — Real-time refresh of assigned clients (MAC address / IP address / hostname / lease remaining)
- **Full DHCP Protocol** — RFC 2131 compliant, supports Discover → Offer → Request → Ack complete flow
- **Multi-Language Support** — 10 languages with auto-detection and manual switching

## Supported Languages

| Language | Native Name |
|----------|-------------|
| English | English |
| Chinese | 中文 |
| Hindi | हिन्दी |
| Spanish | Español |
| French | Français |
| Arabic | العربية |
| Bengali | বাংলা |
| Russian | Русский |
| Portuguese | Português |
| Japanese | 日本語 |

The tool automatically detects your system language on startup. You can also switch languages anytime using the dropdown in the top bar.

## Usage

1. **Download** — Get the latest `DHCPTool.exe` from [Releases](https://github.com/liang0331/Windows-DHCP-Tool/releases)
2. **Run** — Double-click `DHCPTool.exe` (UAC prompt will appear, click "Yes" to grant admin privileges)
3. **Select Adapter** — Choose the network adapter you want to provide DHCP service on (internal adapter recommended)
4. **Configure IP Range** — Fill in the IP allocation range, default values usually work fine
5. **Start** — Click "▶ Start DHCP", firewall rules are auto-configured, status bar shows "Firewall: UDP 67/68 allowed"
6. **Other devices on the same network segment will automatically obtain IP addresses**

## Development

```bash
# Clone the repository
git clone https://github.com/liang0331/Windows-DHCP-Tool.git
cd Windows-DHCP-Tool

# Create virtual environment (Python 3.8+)
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install customtkinter psutil pyinstaller

# Run in debug mode
python dhcptool\main.py

# Build exe
pyinstaller --onefile --windowed --uac-admin --name DHCPTool --collect-all customtkinter --hidden-import psutil dhcptool\main.py
```

## System Requirements

- **OS**: Windows 10 / Windows 11 (64-bit)
- **Privileges**: Administrator (required to bind UDP port 67)
- **Dependencies**: None — single-file exe, works out of the box

## FAQ

**Q: Why is administrator privilege required?**
The standard DHCP server port UDP 67 requires admin privileges to bind. The exe has an embedded UAC manifest and will automatically request elevation on launch.

**Q: Clients cannot obtain IP?**
- Check if the status bar shows "Firewall: UDP 67/68 allowed"
- Ensure client devices are on the same network segment as the adapter running the DHCP tool
- Check if your switch/router has DHCP Snooping enabled

## Tech Stack

- **Language**: Python 3.13
- **GUI**: customtkinter (modern dark-themed tkinter)
- **DHCP Core**: Pure Python socket implementation (RFC 2131)
- **Packaging**: PyInstaller (single-file exe with UAC manifest)
- **Network Info**: psutil

## License

MIT License

## Download

- **GitHub Releases**: [latest version](https://github.com/liang0331/Windows-DHCP-Tool/releases)
- **Gitee (China mirror)**: [https://gitee.com/LLL0558/Windows-DHCP-Tool](https://gitee.com/LLL0558/Windows-DHCP-Tool)
