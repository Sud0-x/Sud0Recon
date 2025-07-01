# 🚀 Sud0Recon Quick Start Guide

**Sud0Recon** now has a **single, universal launcher** that makes everything super easy!

## 📍 Location

The main launcher is located at: **`./sud0recon`** (in the root directory)

## ⚡ Quick Start

### 1. First Time Setup
```bash
./sud0recon setup
```
This automatically installs all dependencies and sets up the environment.

### 2. Basic Scanning
```bash
# Scan a single target
./sud0recon -t example.com

# Scan multiple targets  
./sud0recon -t google.com,github.com

# Aggressive scan (all features)
./sud0recon -t example.com -A
```

### 3. Utility Commands
```bash
./sud0recon help        # Show quick help
./sud0recon demo        # Run interactive demo
./sud0recon view        # View latest scan report
./sud0recon list        # List all scan reports
```

### 4. Advanced Options
```bash
# Full help menu
./sud0recon --help

# Custom settings
./sud0recon -t example.com --threads 20 --timeout 15

# Different output formats
./sud0recon -t example.com -o json,html

# Enable specific scans
./sud0recon -t example.com --subdomain-enum --port-scan
```

## 🎯 Key Benefits

✅ **Single File**: Only one launcher to remember (`./sud0recon`)  
✅ **Auto Setup**: Automatically handles first-time setup  
✅ **Built-in Utils**: Report viewing, listing, and demo all integrated  
✅ **Easy Location**: Located in the main directory, easy to find  
✅ **Color Coded**: Beautiful colored output for better readability  
✅ **Random Banner**: Different colorful banner each time you run it!  

## 📁 File Structure

```
Sud0Recon/
├── sud0recon           ← MAIN LAUNCHER (use this!)
├── src/                ← Source code
├── reports/            ← Scan reports saved here
├── venv/               ← Python virtual environment (auto-created)
└── requirements.txt    ← Dependencies
```

## 🆘 Need Help?

- **Quick help**: `./sud0recon help`
- **Full options**: `./sud0recon --help`  
- **Run demo**: `./sud0recon demo`
- **Contact**: sud0x.dev@proton.me
- **GitHub**: github.com/Sud0-x/Sud0Recon

---

🔥 **That's it! Everything you need is in one simple command: `./sud0recon`**
