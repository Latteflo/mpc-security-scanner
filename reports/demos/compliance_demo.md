# 🔒 Compliance Assessment Report
**Generated:** 2025-10-16 21:45:24
**Target:** http://localhost:3000
**Server Name:** Test Vulnerable Server
**Total Vulnerabilities:** 8

---
## Executive Summary
This compliance assessment identified **8 security issues** affecting **6 compliance frameworks**.

## Framework Compliance Status

| Framework | Status | Affected Controls | Critical | High |
|-----------|--------|-------------------|----------|------|
| ISO/IEC 27001:2013 | ❌ Non-Compliant | 8 | 2 | 2 |
| NIST Cybersecurity Framework | ❌ Non-Compliant | 4 | 2 | 2 |
| NIST SP 800-53 Rev. 5 | ❌ Non-Compliant | 8 | 2 | 2 |
| MITRE ATT&CK Framework | ❌ Non-Compliant | 3 | 2 | 2 |
| PCI DSS 3.2.1 | ❌ Non-Compliant | 3 | 2 | 2 |
| SOC 2 Type II | ❌ Non-Compliant | 2 | 2 | 2 |

---

## ISO/IEC 27001:2013

**Status:** NON_COMPLIANT
**Risk Level:** HIGH
**Affected Controls:** 8

### Affected Controls

| Control ID | Control Name | Category |
|------------|--------------|----------|
| A.10.1.1 | Policy on the Use of Cryptographic Controls | Cryptography |
| A.13.1.1 | Network Controls | Communications Security |
| A.13.2.1 | Information Transfer Policies and Procedures | Communications Security |
| A.14.2.1 | Secure Development Policy | System Acquisition, Development and Maintenance |
| A.14.2.5 | Secure System Engineering Principles | System Acquisition, Development and Maintenance |
| A.9.2.1 | User Registration and De-registration | Access Control |
| A.9.4.1 | Information Access Restriction | Access Control |
| A.9.4.2 | Secure Log-on Procedures | Access Control |


## NIST Cybersecurity Framework

**Status:** NON_COMPLIANT
**Risk Level:** MEDIUM
**Affected Controls:** 4

### Affected Controls

| Control ID | Control Name | Category |
|------------|--------------|----------|
| PR.AC-1 | Identities and Credentials Management | Protect - Access Control |
| PR.AC-7 | Users, Devices, and Assets Authentication | Protect - Access Control |
| PR.DS-2 | Data-in-transit Protection | Protect - Data Security |
| PR.IP-1 | Baseline Configuration | Protect - Information Protection Processes |


## NIST SP 800-53 Rev. 5

**Status:** NON_COMPLIANT
**Risk Level:** HIGH
**Affected Controls:** 8

### Affected Controls

| Control ID | Control Name | Category |
|------------|--------------|----------|
| AC-2 | Account Management | Access Control |
| AC-3 | Access Enforcement | Access Control |
| AC-6 | Least Privilege | Access Control |
| CM-7 | Least Functionality | Configuration Management |
| IA-2 | Identification and Authentication (Organizational Users) | Identification and Authentication |
| SC-13 | Cryptographic Protection | System and Communications Protection |
| SC-8 | Transmission Confidentiality and Integrity | System and Communications Protection |
| SI-10 | Information Input Validation | System and Information Integrity |


## MITRE ATT&CK Framework

**Status:** NON_COMPLIANT
**Risk Level:** MEDIUM
**Affected Controls:** 3

### Affected Controls

| Control ID | Control Name | Category |
|------------|--------------|----------|
| T1040 | Network Sniffing | Credential Access, Discovery |
| T1078 | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion |
| T1557 | Adversary-in-the-Middle | Credential Access, Collection |


## PCI DSS 3.2.1

**Status:** NON_COMPLIANT
**Risk Level:** MEDIUM
**Affected Controls:** 3

### Affected Controls

| Control ID | Control Name | Category |
|------------|--------------|----------|
| 4.1 | Use Strong Cryptography for Cardholder Data Transmission | Requirement 4 - Encrypt transmission of cardholder data |
| 6.5.1 | Injection Flaws | Requirement 6 - Develop and maintain secure systems |
| 8.2 | User Authentication and Password Management | Requirement 8 - Identify and authenticate access |


## SOC 2 Type II

**Status:** NON_COMPLIANT
**Risk Level:** LOW
**Affected Controls:** 2

### Affected Controls

| Control ID | Control Name | Category |
|------------|--------------|----------|
| CC6.1 | Logical and Physical Access Controls | Common Criteria - Logical and Physical Access Controls |
| CC6.6 | Transmission of Data | Common Criteria - Logical and Physical Access Controls |

## Remediation Recommendations

### Critical Priority

1. **Missing Authentication** (MCP-AUTH-001)
   - The MCP server at http://localhost:3000 does not require authentication. Any client can connect and ...
   - Affects 6 frameworks

2. **Dangerous Tools Exposed Without Authorization** (MCP-AUTHZ-001)
   - The MCP server exposes 3 potentially dangerous tools without proper authorization controls. Combined...
   - Affects 3 frameworks

