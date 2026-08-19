---
name: performing-threat-intelligence-sharing-with-misp
description: Use PyMISP to create, enrich, and share threat intelligence events on a MISP platform, including IOC management,
  feed integration, STIX export, and community sharing workflows.
domain: cybersecurity
subdomain: threat-intelligence
tags:
- misp
- pymisp
- threat-intelligence
- ioc-sharing
- stix
- taxii
- threat-feeds
- information-sharing
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
---
# Performing Threat Intelligence Sharing with MISP

## Overview

MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform designed for collecting, storing, distributing, and sharing cybersecurity indicators and threat information. PyMISP is the official Python library for interacting with MISP instances via the REST API, enabling programmatic event creation, attribute management, tag assignment, galaxy cluster attachment, and feed synchronization. This skill covers using PyMISP to create events with structured IOCs (IP addresses, domains, file hashes, URLs), enrich events with MITRE ATT&CK tags, manage sharing groups and distribution levels, search for existing intelligence, and export in STIX 2.1 format for interoperability with other platforms.


## When to Use

- When conducting security assessments that involve performing threat intelligence sharing with misp
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Detection Gaps & Validation

- **Distribution misconfiguration leaks intel:** the most damaging error is a wrong `distribution` level or sharing-group scope - publishing a TLP:RED event with "All communities" distribution, or adding it to a sync server that forwards onward. Verify the event distribution, every attribute's distribution (attributes can override the event), and the sharing-group member list **before** `publish()`; once synced it cannot be recalled.
- **to_ids / IDS-flag gaps:** attributes can push benign or context-only indicators (sinkholes, your own infrastructure, sandbox IPs) into partners' detection systems. Set `to_ids=False` on context attributes and run MISP warninglists (RFC1918, known-good domains, public DNS resolvers) before publishing.
- **Correlation/dedup blind spots:** the same IOC arriving from multiple feeds creates duplicate events and inflated confidence; run `misp.search()` and rely on MISP correlation before creating a new event so you enrich the existing one instead of forking it.
- **How to confirm a share is safe:** dry-run with a restricted distribution first, confirm TLP tags map to the intended sharing group, and validate the STIX 2.1 export round-trips (re-import and diff) so downstream consumers receive well-formed, correctly marked objects.

## Prerequisites

- MISP instance (v2.4+) with API access enabled
- Python 3.9+ with `pymisp` (`pip install pymisp`)
- MISP API key (Settings > Auth Keys)
- Understanding of MISP data model (Events, Attributes, Objects, Tags, Galaxies)
- Knowledge of TLP marking and sharing protocols

## Steps

1. Install PyMISP: `pip install pymisp`
2. Initialize `ExpandedPyMISP(url, key, ssl=True)` connection
3. Create a `MISPEvent` with info, distribution level, threat level, and analysis status
4. Add attributes via `event.add_attribute(type, value)` for IPs, domains, hashes
5. Apply TLP tags and MITRE ATT&CK technique tags
6. Publish the event with `misp.publish(event)`
7. Search existing events with `misp.search(controller='events', value=..., type_attribute=...)`
8. Enable and configure threat feeds for automatic IOC ingestion
9. Export events in STIX 2.1 format for cross-platform sharing
10. Validate sharing group configuration and sync server settings

## Expected Output

A JSON report summarizing events created, attributes added, tags applied, feed sync status, and any correlation hits against existing intelligence, with event IDs and distribution metadata.
