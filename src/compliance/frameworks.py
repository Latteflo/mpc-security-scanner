"""
Compliance Framework Definitions
ISO 27001, NIST CSF, NIST 800-53, MITRE ATT&CK, PCI DSS, SOC2
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    ISO27001 = "ISO27001"
    NIST_CSF = "NIST_CSF"
    NIST_800_53 = "NIST_800_53"
    MITRE_ATTCK = "MITRE_ATTCK"
    PCI_DSS = "PCI_DSS"
    SOC2 = "SOC2"
    GDPR = "GDPR"
    HIPAA = "HIPAA"


@dataclass
class FrameworkControl:
    """Represents a control from a compliance framework"""
    id: str
    name: str
    description: str
    framework: ComplianceFramework
    category: str
    
    def __hash__(self):
        return hash(f"{self.framework.value}-{self.id}")
    
    def __eq__(self, other):
        if not isinstance(other, FrameworkControl):
            return False
        return self.framework == other.framework and self.id == other.id
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'framework': self.framework.value,
            'category': self.category
        }


# ISO 27001:2013 Controls
ISO27001_CONTROLS = {
    "A.9.2.1": FrameworkControl(
        id="A.9.2.1",
        name="User Registration and De-registration",
        description="A formal user registration and de-registration process shall be implemented to enable assignment of access rights",
        framework=ComplianceFramework.ISO27001,
        category="Access Control"
    ),
    "A.9.4.2": FrameworkControl(
        id="A.9.4.2",
        name="Secure Log-on Procedures",
        description="Where required by the access control policy, access to systems and applications shall be controlled by a secure log-on procedure",
        framework=ComplianceFramework.ISO27001,
        category="Access Control"
    ),
    "A.9.4.1": FrameworkControl(
        id="A.9.4.1",
        name="Information Access Restriction",
        description="Access to information and application system functions shall be restricted in accordance with the access control policy",
        framework=ComplianceFramework.ISO27001,
        category="Access Control"
    ),
    "A.10.1.1": FrameworkControl(
        id="A.10.1.1",
        name="Policy on the Use of Cryptographic Controls",
        description="A policy on the use of cryptographic controls for protection of information shall be developed and implemented",
        framework=ComplianceFramework.ISO27001,
        category="Cryptography"
    ),
    "A.10.1.2": FrameworkControl(
        id="A.10.1.2",
        name="Key Management",
        description="A policy on the use, protection and lifetime of cryptographic keys shall be developed and implemented",
        framework=ComplianceFramework.ISO27001,
        category="Cryptography"
    ),
    "A.13.1.1": FrameworkControl(
        id="A.13.1.1",
        name="Network Controls",
        description="Networks shall be managed and controlled to protect information in systems and applications",
        framework=ComplianceFramework.ISO27001,
        category="Communications Security"
    ),
    "A.13.2.1": FrameworkControl(
        id="A.13.2.1",
        name="Information Transfer Policies and Procedures",
        description="Formal transfer policies, procedures and controls shall be in place to protect the transfer of information",
        framework=ComplianceFramework.ISO27001,
        category="Communications Security"
    ),
    "A.14.2.1": FrameworkControl(
        id="A.14.2.1",
        name="Secure Development Policy",
        description="Rules for the development of software and systems shall be established and applied to developments within the organization",
        framework=ComplianceFramework.ISO27001,
        category="System Acquisition, Development and Maintenance"
    ),
    "A.14.2.5": FrameworkControl(
        id="A.14.2.5",
        name="Secure System Engineering Principles",
        description="Principles for engineering secure systems shall be established, documented, maintained and applied",
        framework=ComplianceFramework.ISO27001,
        category="System Acquisition, Development and Maintenance"
    ),
    "A.12.2.1": FrameworkControl(
        id="A.12.2.1",
        name="Controls Against Malware",
        description="Detection, prevention and recovery controls to protect against malware shall be implemented",
        framework=ComplianceFramework.ISO27001,
        category="Operations Security"
    ),
    "A.12.6.1": FrameworkControl(
        id="A.12.6.1",
        name="Management of Technical Vulnerabilities",
        description="Information about technical vulnerabilities shall be obtained in a timely fashion",
        framework=ComplianceFramework.ISO27001,
        category="Operations Security"
    ),
    "A.17.2.1": FrameworkControl(
        id="A.17.2.1",
        name="Availability of Information Processing Facilities",
        description="Information processing facilities shall be implemented with redundancy sufficient to meet availability requirements",
        framework=ComplianceFramework.ISO27001,
        category="Information Security Aspects of Business Continuity Management"
    ),
}

# NIST Cybersecurity Framework
NIST_CSF_CONTROLS = {
    "PR.AC-1": FrameworkControl(
        id="PR.AC-1",
        name="Identities and Credentials Management",
        description="Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
        framework=ComplianceFramework.NIST_CSF,
        category="Protect - Access Control"
    ),
    "PR.AC-7": FrameworkControl(
        id="PR.AC-7",
        name="Users, Devices, and Assets Authentication",
        description="Users, devices, and other assets are authenticated commensurate with the risk of the transaction",
        framework=ComplianceFramework.NIST_CSF,
        category="Protect - Access Control"
    ),
    "PR.DS-2": FrameworkControl(
        id="PR.DS-2",
        name="Data-in-transit Protection",
        description="Data-in-transit is protected",
        framework=ComplianceFramework.NIST_CSF,
        category="Protect - Data Security"
    ),
    "DE.AE-5": FrameworkControl(
        id="DE.AE-5",
        name="Incident Alert Thresholds",
        description="Incident alert thresholds are established",
        framework=ComplianceFramework.NIST_CSF,
        category="Detect - Anomalies and Events"
    ),
    "PR.IP-1": FrameworkControl(
        id="PR.IP-1",
        name="Baseline Configuration",
        description="A baseline configuration of information technology/industrial control systems is created and maintained",
        framework=ComplianceFramework.NIST_CSF,
        category="Protect - Information Protection Processes"
    ),
}

# NIST 800-53 Rev 5
NIST_800_53_CONTROLS = {
    "IA-2": FrameworkControl(
        id="IA-2",
        name="Identification and Authentication (Organizational Users)",
        description="Uniquely identify and authenticate organizational users and associate that unique identification with processes",
        framework=ComplianceFramework.NIST_800_53,
        category="Identification and Authentication"
    ),
    "AC-2": FrameworkControl(
        id="AC-2",
        name="Account Management",
        description="Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts",
        framework=ComplianceFramework.NIST_800_53,
        category="Access Control"
    ),
    "AC-3": FrameworkControl(
        id="AC-3",
        name="Access Enforcement",
        description="Enforce approved authorizations for logical access to information and system resources",
        framework=ComplianceFramework.NIST_800_53,
        category="Access Control"
    ),
    "AC-6": FrameworkControl(
        id="AC-6",
        name="Least Privilege",
        description="Employ the principle of least privilege, allowing only authorized accesses for users",
        framework=ComplianceFramework.NIST_800_53,
        category="Access Control"
    ),
    "SC-8": FrameworkControl(
        id="SC-8",
        name="Transmission Confidentiality and Integrity",
        description="Protect the confidentiality and integrity of transmitted information",
        framework=ComplianceFramework.NIST_800_53,
        category="System and Communications Protection"
    ),
    "SC-13": FrameworkControl(
        id="SC-13",
        name="Cryptographic Protection",
        description="Implement required cryptographic protections using cryptographic modules",
        framework=ComplianceFramework.NIST_800_53,
        category="System and Communications Protection"
    ),
    "SC-5": FrameworkControl(
        id="SC-5",
        name="Denial of Service Protection",
        description="Protect against or limit the effects of denial of service attacks",
        framework=ComplianceFramework.NIST_800_53,
        category="System and Communications Protection"
    ),
    "SI-10": FrameworkControl(
        id="SI-10",
        name="Information Input Validation",
        description="Check the validity of information inputs",
        framework=ComplianceFramework.NIST_800_53,
        category="System and Information Integrity"
    ),
    "CM-7": FrameworkControl(
        id="CM-7",
        name="Least Functionality",
        description="Configure systems to provide only essential capabilities",
        framework=ComplianceFramework.NIST_800_53,
        category="Configuration Management"
    ),
}

# MITRE ATT&CK Techniques
MITRE_ATTCK_TECHNIQUES = {
    "T1078": FrameworkControl(
        id="T1078",
        name="Valid Accounts",
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Initial Access, Persistence, Privilege Escalation, Defense Evasion"
    ),
    "T1040": FrameworkControl(
        id="T1040",
        name="Network Sniffing",
        description="Adversaries may sniff network traffic to capture information about an environment",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Credential Access, Discovery"
    ),
    "T1557": FrameworkControl(
        id="T1557",
        name="Adversary-in-the-Middle",
        description="Adversaries may attempt to position themselves between two or more networked devices",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Credential Access, Collection"
    ),
    "T1189": FrameworkControl(
        id="T1189",
        name="Drive-by Compromise",
        description="Adversaries may gain access to a system through a user visiting a website over the normal course of browsing",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Initial Access"
    ),
    "T1499": FrameworkControl(
        id="T1499",
        name="Endpoint Denial of Service",
        description="Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Impact"
    ),
    "T1190": FrameworkControl(
        id="T1190",
        name="Exploit Public-Facing Application",
        description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Initial Access"
    ),
    "T1059": FrameworkControl(
        id="T1059",
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Execution"
    ),
    "T1083": FrameworkControl(
        id="T1083",
        name="File and Directory Discovery",
        description="Adversaries may enumerate files and directories or may search in specific locations of a host or network share",
        framework=ComplianceFramework.MITRE_ATTCK,
        category="Discovery"
    ),
}

# PCI DSS 3.2.1 Requirements
PCI_DSS_CONTROLS = {
    "4.1": FrameworkControl(
        id="4.1",
        name="Use Strong Cryptography for Cardholder Data Transmission",
        description="Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission",
        framework=ComplianceFramework.PCI_DSS,
        category="Requirement 4 - Encrypt transmission of cardholder data"
    ),
    "6.5.1": FrameworkControl(
        id="6.5.1",
        name="Injection Flaws",
        description="Address common coding vulnerabilities in software-development processes, particularly injection flaws",
        framework=ComplianceFramework.PCI_DSS,
        category="Requirement 6 - Develop and maintain secure systems"
    ),
    "8.2": FrameworkControl(
        id="8.2",
        name="User Authentication and Password Management",
        description="Assign a unique ID to each person with computer access",
        framework=ComplianceFramework.PCI_DSS,
        category="Requirement 8 - Identify and authenticate access"
    ),
}

# SOC 2 Criteria
SOC2_CONTROLS = {
    "CC6.1": FrameworkControl(
        id="CC6.1",
        name="Logical and Physical Access Controls",
        description="The entity implements logical access security software, infrastructure, and architectures",
        framework=ComplianceFramework.SOC2,
        category="Common Criteria - Logical and Physical Access Controls"
    ),
    "CC6.6": FrameworkControl(
        id="CC6.6",
        name="Transmission of Data",
        description="The entity implements logical access security measures to protect against threats from sources outside its system boundaries",
        framework=ComplianceFramework.SOC2,
        category="Common Criteria - Logical and Physical Access Controls"
    ),
    "CC7.2": FrameworkControl(
        id="CC7.2",
        name="System Monitoring",
        description="The entity monitors system components and the operation of those components for anomalies",
        framework=ComplianceFramework.SOC2,
        category="Common Criteria - System Operations"
    ),
}
