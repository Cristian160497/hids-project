# HIDS - Host Intrusion Detection System

Implementation of a host-based intrusion detection system for Windows systems. The process monitors four attack surfaces targeted during system attacks: monitoring critical system files, monitoring system logs, monitoring network connections and monitoring system processes. Detection is performed following precise rules based on the main attack techniques mapped within the MITRE ATT&CK framework. 

---

## Motivation

This project was built from scratch in Python rather than using existing tools of infrastructure for several concrete reasons.

**Network-level detection was not feasible:** the initial goal was to deploy the system on the home WiFi network. However, the available router falls into the 4/32 hardware category - 4MB Flash and 32MB RAM - explicitly marked as unsupported by recent OpenWrt versions. Without a custom firmware, full traffic visibility was not achievable.

**Cloud infrastructure was not an option:** deploying Wazuh components on cloud providers (Google Cloud, Oracle Cloud) was evaluated as an alternative. Both platforms require a credit or debit card for registration - including their free tiers - ruling out this approach without any financial investment.

**Resource constraints on local hardware:** a full Wazuh stack requires a minimum of 8GB RAM dedicated to its comoponents alone. The available machine runs Windows 11 on an entry-level processor with 8GB total RAM shared with the operating system, making a local virtualized deployment unfeasible.

**Learning objectives.** building a custom HIDS from scratch in Python provides genuine understanding of how intrusion detection systems work internally. Every architectural decision was made deliberately and documented - from Windows Event Log parsing to SHA-256 file integrity verification and process masquerading detection - rather than delegated to a pre-built tool.

## Architecture

## Modules

## Installation

## Usage

## Technical Decision

## Known Limitations

## Roadmap