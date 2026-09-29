# Security MCP Server

A Python-based Model Context Protocol (MCP) server that exposes practical cybersecurity analysis capabilities to AI applications through standardized MCP tools.

The server provides local security analysis for IP addresses, hashes, and domains, and can enrich indicators with external threat intelligence from VirusTotal.

---

## Overview

Modern security workflows often require analysts to combine multiple tools and sources of information when investigating an indicator of compromise (IOC).

The Security MCP Server provides a unified interface for common IOC analysis tasks.

Instead of an AI application needing separate integrations for every security utility, the MCP server exposes standardized tools that can be discovered and invoked through the Model Context Protocol.

### Disclaimer

This project is intended for cybersecurity research, automation, learning, and authorized security analysis.

Only analyze systems, indicators, and data that you are authorized to investigate.

External threat-intelligence services may have their own terms, rate limits, privacy policies, and data-handling considerations.



### Core workflow

```text
                    AI / MCP CLIENT
                          │
                          ▼
                Security MCP Server
                          │
                 analyze_indicator()
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
            IP          DOMAIN        HASH
             │            │            │
        Local Analysis  DNS Analysis  Hash Analysis
             │            │            │
             └────────────┼────────────┘
                          ▼
                   VirusTotal API
                          │
                          ▼
                Threat Intelligence
                          │
                          ▼
                  Structured Result


Features
IOC Analysis

The unified analyze_indicator tool automatically identifies and analyzes:

IPv4 and IPv6 addresses
File hashes
Domain names
IP Analysis

Provides basic security-relevant properties including:

IP version
Private/public classification
Loopback detection
Multicast detection
Reserved-address detection
Hash Analysis

Performs structural analysis of hexadecimal hashes:

Hexadecimal validation
Hash length
Possible algorithm identification
MD5
SHA-1
SHA-256
SHA-384
SHA-512

Algorithm identification is based on structural characteristics and is therefore reported as a possible algorithm rather than a definitive identification.

DNS Resolution

Resolves domains and separates:

IPv4 addresses
IPv6 addresses
Domain Investigation

Combines DNS resolution with IP analysis to provide a basic investigation workflow for domains.

VirusTotal Intelligence

The server can enrich:

IP addresses
Domains
File hashes

using the VirusTotal API.

The extracted intelligence includes relevant metadata and analysis statistics.

Normalized Threat Assessment

VirusTotal analysis statistics are normalized into a consistent assessment structure:  

{
  "malicious_detections": 2,
  "suspicious_detections": 1,
  "harmless_detections": 50,
  "undetected_detections": 10,
  "timeout_detections": 0,
  "total_engines": 63,
  "detection_ratio": 0.0476
}

The server reports evidence from the intelligence source rather than declaring an indicator inherently "safe" or "malicious" based on a single metric.

External Lookup Control

External threat-intelligence lookups can be disabled:

analyze_indicator(
    indicator,
    external_lookup=False
)

When disabled:

Local analysis
     │
     ▼
Structured result

VirusTotal
     │
     └── Not contacted

This allows potentially sensitive indicators to be analyzed locally without automatically submitting them to an external intelligence provider.

Structured Logging

Application events are written to:
logs/security_mcp.log

The logging layer records operational information while avoiding logging complete IOC values in the hardened application workflow.

Error Handling

The VirusTotal integration handles:

HTTP errors
Request timeouts
Invalid JSON responses
Missing API configuration

External intelligence failures do not need to prevent local IOC analysis from being performed.

MCP Tools

The server currently exposes the following MCP tools:

| Tool                 | Purpose                                   |
| -------------------- | ----------------------------------------- |
| `hello_security`     | Basic server connectivity test            |
| `analyze_ip`         | Analyze IP address properties             |
| `analyze_hash`       | Analyze hash structure                    |
| `resolve_dns`        | Resolve domain addresses                  |
| `investigate_domain` | Resolve and analyze a domain              |
| `analyze_indicator`  | Unified IOC classification and enrichment |


The primary workflow is:
analyze_indicator
        │
        ├── IP
        │    ├── Local IP analysis
        │    └── VirusTotal IP intelligence
        │
        ├── Domain
        │    ├── DNS investigation
        │    └── VirusTotal domain intelligence
        │
        └── Hash
             ├── Hash analysis
             └── VirusTotal hash intelligence


Project Structure:

MCP-Security-Server/
│
├── .venv/
│
├── src/
│   ├── __init__.py
│   │
│   └── security_mcp/
│       ├── __init__.py
│       │
│       ├── intelligence/
│       │   ├── __init__.py
│       │   └── virustotal.py
│       │
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── dns.py
│       │   ├── hash.py
│       │   ├── indicator.py
│       │   ├── investigation.py
│       │   └── ip.py
│       │
│       └── logging_config.py
│
├── tests/
│   ├── __init__.py
│   ├── intelligence/
│   │   └── test_virustotal.py
│   ├── test_dns.py
│   ├── test_hash.py
│   ├── test_indicator.py
│   ├── test_investigation.py
│   └── test_ip.py
│
├── .env.example
├── .gitignore
├── README.md
└── server.py


Architecture

The project separates the MCP interface, security tools, external intelligence, and testing layers.

                         server.py
                            │
                     MCPServer instance
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
        ▼                   ▼                    ▼
      Tools             Intelligence          Logging
        │                   │                    │
        │                   │                    │
        ▼                   ▼                    ▼
   Local Security       VirusTotal          Application
      Analysis            Client              Logging
        │                   │
        └──────────┬────────┘
                   ▼
            Structured Results

server.py

Acts as the MCP entry point.

It:

Creates the MCP server
Registers security tools
Configures application logging
Starts the MCP server using stdio
tools/

Contains local security-analysis functionality.

Responsibilities are separated by capability:

ip.py
    IP analysis

hash.py
    Hash analysis

dns.py
    DNS resolution

investigation.py
    Domain investigation workflow

indicator.py
    Unified IOC classification and orchestration


intelligence/

Contains integrations with external threat-intelligence providers.

Currently:

virustotal.py

The module handles:

API authentication
HTTP requests
Error handling
IP reports
Domain reports
Hash reports
Intelligence extraction
Normalized assessment metrics


tests/
Contains automated tests for the security tools and intelligence layer.

The project uses mocked API responses for deterministic testing instead of making external API requests during normal unit-test execution.


Requirements
Python 3.10+
Internet access for VirusTotal enrichment
A VirusTotal API key for external intelligence lookups

The project was developed and tested using:

Python 3.14
MCP Python SDK 2.x
requests
python-dotenv
pytest


Installation

Clone the repository:
git clone <YOUR-REPOSITORY-URL>
cd MCP-Security-Server

Create a Virtual Environment:
python -m venv .venv

Activate it on Windows:
.venv\Scripts\activate

Install dpenedencies:
pip install -r requirements.txt



Configuration

Create a .env file in the project root:
VT_API_KEY=your_virustotal_api_key_here

A template is provided:

.env.example

The real .env file is excluded from Git through .gitignore.

Never commit a real API key to the repository.



Running the Server

From the project root:

python server.py

The server uses stdio transport, so the process will wait for an MCP client to connect.


MCP Inspector

The project can be tested using MCP Inspector.

Launch Inspector from a separate terminal:

npx @modelcontextprotocol/inspector

Configure the local server using:

Transport:
stdio

Command:
C:\Users\<username>\MCP-Security-Server\.venv\Scripts\python.exe

Arguments:
server.py

Working Directory:
C:\Users\<username>\MCP-Security-Server

After connecting, the available MCP tools can be discovered through the Inspector interface.



Example IOC Analysis
IP Address

Input:

8.8.8.8

The unified tool performs:

IP classification
      ↓
Local IP analysis
      ↓
VirusTotal IP lookup
      ↓
Structured intelligence





Domain

Input:

example.com

The workflow becomes:

Domain classification
       ↓
DNS resolution
       ↓
Resolved IP analysis
       ↓
VirusTotal domain lookup
       ↓
Structured intelligence





Hash

Input:

5d41402abc4b2a76b9719d911017c592

The workflow becomes:

Hash classification
       ↓
Structural analysis
       ↓
VirusTotal file lookup
       ↓
Structured intelligence



Testing

The project uses pytest.

Run the complete test suite:

python -m pytest

The current test suite contains:

39 passed

The tests cover:

IP analysis
Hash analysis
DNS resolution
Domain investigation
IOC classification
IOC normalization
VirusTotal API integration
VirusTotal error handling
Invalid JSON responses
Request timeouts
HTTP errors
Missing API configuration
Intelligence extraction
Normalized assessment metrics
External lookup disabling
Local analysis without external enrichment

External VirusTotal requests are mocked during automated testing.



Security and Privacy Considerations



API Keys
VirusTotal credentials are loaded from environment variables:

VT_API_KEY

Real credentials should never be committed to Git.


External IOC Submission
When VirusTotal enrichment is enabled, the queried indicator is sent to VirusTotal.

Therefore, sensitive or confidential indicators should not be submitted unless the user or organization has explicitly determined that doing so is appropriate.

For indicators that should remain local, disable external enrichment:

external_lookup=False


Logging
Application logging is designed to record operational events without storing complete IOC values in the hardened classification workflow.

Logs are stored locally under:

logs/

The directory is excluded from Git.


Design Principles

The project follows several engineering principles:

Separation of responsibilities

MCP registration, local analysis, external intelligence, logging, and testing are separated into different modules.

Fail gracefully

Failure of an external intelligence provider should not necessarily prevent local security analysis.

Evidence over assumptions

The system exposes intelligence and derived metrics rather than making unsupported claims about whether an indicator is definitively malicious or safe.

Privacy-aware enrichment

External intelligence lookups can be explicitly disabled.

Testability

External API behavior is mocked during automated tests so that the test suite remains deterministic and does not depend on API availability or rate limits.


Current Capabilities

                    Security MCP Server
                            │
                            ▼
                    Unified IOC Engine
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
            IP           DOMAIN           HASH
             │              │              │
         Local IP       DNS + IP       Hash Structure
         Analysis       Analysis          Analysis
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                       VirusTotal
                            │
                            ▼
                   Intelligence Data
                            │
                            ▼
                  Normalized Assessment
                            │
                            ▼
                   Structured MCP Result



Project Status

The core MCP security-analysis workflow is implemented and tested.

Current status:

MCP server implemented
Security analysis tools implemented
Unified IOC analysis implemented
VirusTotal enrichment implemented
IP/domain/hash enrichment supported
External lookup control implemented
Structured logging implemented
Error handling implemented
Automated test suite implemented
MCP Inspector end-to-end testing completed



Future Improvements

Potential future development areas include:

Additional threat-intelligence providers
URL analysis
Certificate intelligence
WHOIS/RDAP enrichment
More advanced IOC correlation
Caching of intelligence results
Configurable rate limiting
Additional MCP resources
Reusable MCP prompts for security investigations
More advanced investigation workflows



Author

Built as a cybersecurity engineering project focused on:

Cybersecurity automation
Threat intelligence
IOC analysis
Python development
MCP
AI-assisted security workflows


## One deliberate choice

I **didn't** put fake badges, fake performance numbers, fake screenshots, or claims like:

> "Enterprise-grade AI threat detection"

because we haven't built those things.

That's important. Your GitHub README should describe **what you actually engineered**, and right now that's already substantial.

### After pasting it

Run:

```cmd
git diff -- README.md

