# 🚀 Sud0Recon - Simple Usage Guide

## ⚡ Super Easy Way (Recommended)

Just run this single command:
```bash
./sud0recon -t example.com
```

That's it! The script will automatically:
- Set up everything on first run
- Activate the virtual environment
- Run the scanner
- Show you the results

## 📋 Common Commands

### Basic Scanning
```bash
./sud0recon -t example.com                    # Scan one target
./sud0recon -t google.com,github.com          # Scan multiple targets
./sud0recon -t example.com --threads 20       # Use 20 threads
./sud0recon --help                            # Show all options
```

### Advanced Options
```bash
./sud0recon -t example.com -A                 # Aggressive scan (all scan types)
./sud0recon -t example.com --subdomain-enum   # Find subdomains
./sud0recon -t example.com --port-scan        # Scan ports
./sud0recon -t example.com -o json,html       # Multiple output formats
./sud0recon -t example.com -v                 # Verbose output
./sud0recon -t example.com --no-terminal      # Skip terminal display, save to file only
```

## 🔧 Manual Setup (Optional)

If you want to set up manually:
```bash
./sud0recon setup                             # Run setup manually
```

## 📝 Files Explained

- `sud0recon` - **Main launcher** (use this for everything!)
- `setup.sh` - Sets up the tool (runs automatically)
- `view-report.sh` - View latest scan report (accessed via launcher)
- `list-reports.sh` - List all scan reports (accessed via launcher)
- `reports/` - Your scan results go here

## 📋 Special Commands

```bash
./sud0recon view                              # View latest report
./sud0recon list                              # List all reports
./sud0recon demo                              # Run demo
./sud0recon setup                             # Manual setup
```

## 💡 Examples

### Quick Test
```bash
./sud0recon -t httpbin.org
```

### Real Reconnaissance
```bash
./sud0recon -t yourtarget.com --subdomain-enum --port-scan -v
```

### Multiple Targets
```bash
./sud0recon -t target1.com,target2.com,target3.com
```

## 📄 Viewing Reports

After each scan, Sud0Recon shows you exactly where the JSON report is saved:

### View Latest Report
```bash
./view-report.sh                              # Interactive report viewer
```

### List All Reports
```bash
./list-reports.sh                             # Show all reports with paths
```

### Manual Viewing
```bash
cat reports/sud0recon_scan_YYYYMMDD_HHMMSS.json    # View specific report
nano reports/sud0recon_scan_YYYYMMDD_HHMMSS.json   # Edit in nano
```

### Find Reports
After scanning, the tool automatically shows:
- 📁 **Full file path** (absolute path)
- 💡 **Quick view commands**
- 💡 **Editor commands**

## 🖥️ Terminal Display

**NEW FEATURE!** Sud0Recon now shows scan results directly in your terminal!

### What You See:
- 📊 **Beautiful summary table** with scan statistics
- 🎯 **Success rate and timing information**
- 📋 **Detailed results for each target** with:
  - ✅ Target status (UP/DOWN)
  - 🔍 Open ports (if found)
  - 🌐 Subdomains (if found)
  - 🛡️ Vulnerabilities (if found)
  - 📅 Timestamps

### Control Options:
```bash
./sud0recon -t example.com              # Show results in terminal + save to file
./sud0recon -t example.com --no-terminal # Save to file only (skip terminal display)
```

### Example Terminal Output:
```
📊 SCAN RESULTS
============================================================
🎯 Scan Summary
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric          ┃        Value        ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ Targets Scanned │          2          │
│ Results Found   │          2          │
│ Success Rate    │       100.0%        │
│ Scan Time       │ 2025-07-01 20:51:51 │
└─────────────────┴─────────────────────┘

📋 Detailed Results:
Target #1: example.com
├── Status: UP
├── Timestamp: 2025-07-01T20:51:51.338906
├── 🔍 Port Information
│   ├── Port 80: Open
│   ├── Port 443: Open
│   └── Port 22: Open
└── 🌐 Subdomains
    ├── • www.example.com
    └── • api.example.com
```

## ⚠️ Important Notes

- Only scan systems you own or have permission to test
- Reports are saved in `reports/` directory
- First run takes longer (installs dependencies)
- Tool works offline after setup

## 📞 Support

Contact: sud0x.dev@proton.me

---

**Made easy by Sud0-x** 🔥
