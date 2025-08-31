### Domain Analyzer

The Domain Analyzer is a versatile command-line and graphical tool designed for cybersecurity reconnaissance. It automates the process of gathering open-source intelligence on a target domain or IP address and leverages a local Large Language Model (LLM) to analyze the raw data and generate a professional, actionable security report.

This project is intended to demonstrate a modern, modular approach to software development, integrating command-line and graphical interfaces with external services and tools for a cohesive user experience.

-----

### Features

  * **Dual Interface Support:** Operate the tool via a command-line interface (CLI) for scripting and automation, or use the intuitive graphical user interface (GUI) for interactive analysis.
  * **Comprehensive Data Gathering:** The tool automatically performs several key reconnaissance actions, including WHOIS, DNS, Nmap, SSL certificate, and HTTP header checks.
  * **LLM-Powered Analysis:** Raw intelligence data is aggregated, formatted, and sent to a local LLM for expert analysis, providing a concise and easy-to-understand report for a non-technical executive audience.
  * **Configurable Settings:** Customize LLM API parameters, such as the host, model, and timeout, via a simple `config.toml` file.
  * **Mock Data Generation:** Generate reports from predefined mock data scenarios for testing and development, eliminating the need for a live network connection.
  * **Persistent Reporting:** All generated reports are automatically saved to a local directory for historical tracking and review.

-----

### Intended Use Case

The Domain Analyzer is specifically designed for assessing the security posture of small to medium-sized websites. These sites, which often run on simpler infrastructure, are the perfect use case for the tool.

The tool excels in these environments because:

  * **Simpler Infrastructure:** Smaller sites typically run on a single server or a straightforward hosting platform, making their infrastructure easier to analyze.
  * **Consistent Responses:** DNS records and HTTP headers on these sites are less likely to change frequently. This ensures that the tool consistently gathers complete and reliable data, leading to more accurate reports.

While it's a powerful tool, it's not designed to handle the complexities of large, globally distributed websites used by major tech corporations. The tool is built to provide valuable insights for the majority of the web.

-----

### Installation and Setup

#### 1\. Prerequisites

Ensure the following tools are installed and available in your system's PATH:

  * **Python 3.x**
  * `whois`
  * `dig` (part of `dnsutils` on Debian/Ubuntu)
  * `nmap`
  * `openssl`
  * `curl`

#### 2\. Dependencies

Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

#### 3\. Configuration

Edit the `config.toml` file to point to your local LLM API server. For example, if you are using LM Studio, configure the `host` and `model` as follows:

```toml
[llm]
host = "192.168.0.52:1234"
model = "mistral-nemo-instruct-2407"
timeout = 4800

[paths]
reports_dir = "reports"
```

-----

### Usage

#### Command-Line Interface (CLI)

To run a security analysis from the command line, simply provide the domain or IP as an argument:

```bash
python main.py example.com
```

To generate a report from mock data:

```bash
python main.py --mock-data vulnerable
```

#### Graphical User Interface (GUI)

To launch the GUI, use the `--gui` flag:

```bash
python main.py --gui
```

The GUI allows you to enter a domain, initiate a scan, and view live status updates and generated reports.

-----

### Project Structure

```
.
├── config.toml               # Configuration file for LLM and paths
├── main.py                   # Main entry point for CLI and GUI
├── prompts                   # Contains the LLM prompt template
│   └── llm_prompt.txt
├── reports                   # Directory for saving generated reports
├── requirements.txt          # Python package dependencies
├── scan.sh                   # Standalone shell script for manual scanning
└── src                       # Source code directory
    ├── clients.py            # LLM API client
    ├── core.py               # Core analysis and report generation logic
    ├── exceptions.py         # Custom exceptions for robust error handling
    ├── gui.py                # Graphical user interface module
    └── mock_data_generator.py # Generates mock data for testing
```

-----




### License
This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.










<img width="1903" height="761" alt="Screenshot_mock_data" src="https://github.com/user-attachments/assets/fc1149ed-ccd3-4a5c-9dea-baa09edb9f46" />











