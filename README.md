# Domain Analyzer - Advanced Domain Intelligence & History Analyzer

**Domain Analyzer** is a powerful Python-based OSINT (Open Source Intelligence) tool designed for IT specialists, System Administrators, and Cybersecurity analysts. It provides a deep dive into a target domain's current infrastructure and performs a historical analysis of its hosting history using Passive DNS scraping.

The tool generates a professional, multi-sheet Excel report with visual formatting, making it ideal for auditing and reporting.

## 🚀 Key Features

* **Current Infrastructure Analysis:**
    * Resolves current IP address.
    * Fetches GeoIP data (Country, City, Coordinates).
    * Identifies ISP and ASN (Autonomous System Number).
    * Retrieves WHOIS data (Registrar, Contact Emails) with **silent error handling** for strict TLDs (e.g., `.tr` domains).
* **Historical Analysis (Time Machine):**
    * Scrapes and parses historical 'A' records via RapidDNS.
    * Uses **Smart Regex Parsing** to accurately identify IPs and dates regardless of HTML column changes.
    * Analyzes the GeoIP and ISP ownership of *past* IP addresses to track hosting migrations.
* **Professional Reporting:**
    * Exports data to **Excel (.xlsx)**.
    * **Sheet 1:** Current Status summary.
    * **Sheet 2:** Historical Logs with **boxed formatting** for visual clarity.
* **Resilience:**
    * Includes rate-limiting to avoid API bans.
    * User-Agent spoofing to bypass basic anti-bot protections.

## 💻 Compatibility & Requirements

This script is written in **Python 3** and is cross-platform.

### Operating Systems
* **macOS:** Verified on macOS 10.15 (Catalina) through macOS 15 (Sequoia).
* **Linux:** Compatible with most distributions (Ubuntu, Debian, Kali Linux, CentOS).
* **Windows:** Windows 10/11 (via PowerShell or CMD).

### Python Version
* Python 3.6 or higher.

## 📦 Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/tansuekinci/domain_analyzer/domain-analyzer.git]
    cd domain-analyzer
    ```

2.  **Install Dependencies:**
    You need to install the required modules using `pip` (Python Package Manager).

    **Option A: One-line command**
    ```bash
    pip3 install requests python-whois tabulate beautifulsoup4 pandas openpyxl
    ```

    **Option B: Using requirements.txt (Recommended)**
    Create a file named `requirements.txt` with the content below and run `pip3 install -r requirements.txt`.
    
    *requirements.txt content:*
    ```text
    requests
    python-whois
    tabulate
    beautifulsoup4
    pandas
    openpyxl
    ```

## 🛠 Usage

Run the script using Python 3 from your terminal.

### Method 1: Interactive Mode
Simply run the script. It will ask for the domain name.

```bash
python3 site_analiz.py



Console Output Example

╒════════════════════╤════════════════════════════════════════╕
│ PARAMETER          │ DETAILS                                │
╞════════════════════╪════════════════════════════════════════╡
│ === CURRENT ===    │ ---                                    │
├────────────────────┼────────────────────────────────────────┤
│ Target Domain      │ example.com                            │
├────────────────────┼────────────────────────────────────────┤
│ Current IP         │ 93.184.216.34                          │
├────────────────────┼────────────────────────────────────────┤
│ Location           │ Norwell / United States                │
├────────────────────┼────────────────────────────────────────┤
│ ...                │ ...                                    │
├────────────────────┼────────────────────────────────────────┤
│ === HISTORY ===    │ ---                                    │
├────────────────────┼────────────────────────────────────────┤
│ Detected IP        │ 192.0.2.1                              │
├────────────────────┼────────────────────────────────────────┤
│ Record Date        │ 2023-01-15                             │
╘════════════════════╧════════════════════════════════════════╛

Excel Report
If you choose to save the report, a file named domain.com.xlsx will be created with two sheets:

Current_Status: Snapshot of the current live data.

History_Logs: A visually formatted list of past IP records, with each historical block enclosed in borders.

⚠️ Disclaimer
This tool is for educational and authorized security analysis purposes only. It uses passive scraping and public APIs. Users are responsible for complying with the Terms of Service of the data sources (RapidDNS, IP-API) and local laws regarding network scanning.
