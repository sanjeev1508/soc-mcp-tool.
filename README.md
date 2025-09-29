# SOC MCP Tool

A Python Security Operations Center (SOC) tool suite that detects brute-force attacks and correlates log events using the Model Context Protocol (MCP).

## Overview

This project includes MCP tools for:

- **detect_bruteforce:** Analyze structured logs to identify IP addresses likely performing brute-force attacks, optionally enriched with VirusTotal IP reputation.
- **correlate_events:** Correlate structured logs to generate security alerts, summarize IP and user statistics, and detect suspicious activity patterns.
- **get_ip_details:** Retrieve IP threat intelligence details from VirusTotal via a client-supplied API key.

All tools are implemented asynchronously with clean interfaces and require clients to supply structured event data.

## Features

- Asynchronous Python MCP server implementation with FastMCP
- Integration with VirusTotal IP reputation service (API key optional)
- Flexible brute-force detection configurable by failure thresholds and time windows
- Log event correlation producing alerts and comprehensive statistics
- Designed to run locally without embedded secrets

## Requirements

- Python 3.8+
- `fastmcp` Python package
- `requests` library
