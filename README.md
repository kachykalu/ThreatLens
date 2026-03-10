# ThreatLens

**Automated WAF Analytics Pipeline**

## Overview

ThreatLens is an automated SafeLine Web Application Firewall (WAF) analytics pipeline built using Google Apps Script and Google Sheets. It collects, normalizes, stores, and analyzes security logs from SafeLine WAF API endpoints and generates structured monthly and consolidated dashboards.

---

## Core Capabilities

* Automated ingestion of WAF security records
* Monthly log organization and storage
* Structured multi‑tab classification of log types
* Automatic dashboard generation
* Translation of non‑English log metadata
* Duplicate record prevention
* Scheduled log collection using Apps Script triggers

---

## Log Types Supported

* Attack Records
* Rule Block Records
* Rate Limit Logs
* Anti‑Bot Challenge Logs
* Authentication Challenge Logs
* Authentication Challenge v2 Logs
* Attack Event Records

---

## Dashboard Insights

ThreatLens generates both monthly and consolidated dashboards including:

* Total blocked traffic
* System rule attack detections
* Custom rule / blacklist blocks
* Rate limiting denials
* Anti‑bot challenge triggers
* Authentication defense denials
* Attack event statistics
* Top attacker IP addresses
* Most attacked applications / hosts
* Top source countries
* Attack type distribution
* Risk level distribution
* Most targeted URL paths
* HTTP method distribution
* Protocol usage distribution
* Peak attack hours

---

## Architecture Overview

### 1. Ingestion Layer

ThreatLens pulls paginated data from SafeLine WAF API endpoints using scheduled Apps Script triggers.

### 2. Normalization Layer

Numeric codes from the WAF are mapped into human‑readable values such as attack types, actions, protocols, and risk levels.

### 3. Storage Layer

Logs are written into Google Sheets organized by month and year.

### 4. Analytics Layer

ThreatLens generates dashboards summarizing both monthly and cumulative attack data.

---

## Configuration

ThreatLens uses a configuration object to control core parameters:

* **SAFELINE_HOST** – SafeLine WAF API base URL
* **API_TOKEN** – API authentication token
* **ROOT_FOLDER_NAME** – Google Drive folder used to store logs
* **DASHBOARD_FILE_NAME** – Name of the dashboard spreadsheet
* **PAGE_SIZE** – Number of records per API page
* **MAX_PAGES** – Maximum pages to fetch
* **TRIGGER_INTERVAL_MINUTES** – Automated pull frequency

---

## Workflow

### Initial Setup

Creates the root folder, monthly spreadsheet, dashboard spreadsheet, and automated trigger.

### Scheduled Pull

Fetches data from WAF endpoints, parses records, writes them into monthly sheets, and updates dashboards.

### Dashboard Update

Reads monthly files and aggregates security metrics into a consolidated dashboard.

---

## Google Sheets Output Structure

```
ThreatLens Logs
 ├── 2024
 │   ├── ThreatLens - January 2024
 │   ├── ThreatLens - February 2024
 │   └── ...
 ├── 2025
 │   ├── ThreatLens - January 2025
 │   └── ...
 └── ThreatLens Dashboard
```

---

## Deployment Requirements

* Google account
* Google Apps Script environment
* Access to Google Drive and Google Sheets
* Reachable SafeLine WAF API endpoint
* Valid API token

---

## Permissions Used

ThreatLens requires permissions for:

* SpreadsheetApp
* DriveApp
* UrlFetchApp
* ScriptApp
* LanguageApp
* Utilities
* Logger
---
## Operational Flexibility

ThreatLens is designed to support adjustable ingestion frequency. The trigger schedule can be throttled up or down depending on the volume of traffic and security events entering the SafeLine WAF environment. In lower-volume environments, longer intervals can reduce unnecessary execution overhead. In higher-volume environments, shorter intervals can improve reporting freshness and reduce the size of each processing cycle.

A practical operating model is to tune 'TRIGGER_INTERVAL_MINUTES' based on observed log volume, API response size, Apps Script execution duration, and dashboard update latency. This makes the pipeline more adaptive, efficient, and resilient as data volumes change over time.


---
##Pipeline Screenshots

Note: The following images are screenshots from a production client environment used to demonstrate the ThreatLens pipeline in action. Sensitive information such as hostnames, IP addresses, URLs, and application identifiers has been intentionally masked to protect client confidentiality.
<img width="1914" height="928" alt="WAF11" src="https://github.com/user-attachments/assets/680a5b47-1f91-4579-89e5-bad480e44765" />
<img width="1914" height="928" alt="WAF" src="https://github.com/user-attachments/assets/5e4534d4-2b74-415d-8c58-1632d5421c58" />
<img width="1926" height="875" alt="WAF0" src="https://github.com/user-attachments/assets/2814baa4-f1ec-43f0-959a-7b82e2ce1b40" />
