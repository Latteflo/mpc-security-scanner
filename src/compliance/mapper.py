"""
Compliance Mapper
Maps vulnerabilities to compliance framework controls
"""

import sys
from pathlib import Path
from typing import List, Dict, Set, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from compliance.frameworks import (
    ComplianceFramework,
    FrameworkControl,
    ISO27001_CONTROLS,
    NIST_CSF_CONTROLS,
    NIST_800_53_CONTROLS,
    MITRE_ATTCK_TECHNIQUES,
    PCI_DSS_CONTROLS,
    SOC2_CONTROLS,
)
from utils.logger import get_logger

logger = get_logger("compliance_mapper")


class ComplianceMapper:
    """Maps security vulnerabilities to compliance frameworks"""
    
    def __init__(self):
        self.mappings = self._initialize_mappings()
    
    def _initialize_mappings(self) -> Dict[str, Dict[ComplianceFramework, List[FrameworkControl]]]:
        """Initialize vulnerability ID to framework control mappings"""
        return {
            # Missing Authentication (MCP-AUTH-001)
            "MCP-AUTH-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.9.2.1"],
                    ISO27001_CONTROLS["A.9.4.2"],
                ],
                ComplianceFramework.NIST_CSF: [
                    NIST_CSF_CONTROLS["PR.AC-1"],
                    NIST_CSF_CONTROLS["PR.AC-7"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["IA-2"],
                    NIST_800_53_CONTROLS["AC-2"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1078"],
                ],
                ComplianceFramework.PCI_DSS: [
                    PCI_DSS_CONTROLS["8.2"],
                ],
                ComplianceFramework.SOC2: [
                    SOC2_CONTROLS["CC6.1"],
                ],
            },
            
            # Unencrypted Connection (MCP-CRYPTO-001)
            "MCP-CRYPTO-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.10.1.1"],
                    ISO27001_CONTROLS["A.13.1.1"],
                    ISO27001_CONTROLS["A.13.2.1"],
                ],
                ComplianceFramework.NIST_CSF: [
                    NIST_CSF_CONTROLS["PR.DS-2"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SC-8"],
                    NIST_800_53_CONTROLS["SC-13"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1040"],
                    MITRE_ATTCK_TECHNIQUES["T1557"],
                ],
                ComplianceFramework.PCI_DSS: [
                    PCI_DSS_CONTROLS["4.1"],
                ],
                ComplianceFramework.SOC2: [
                    SOC2_CONTROLS["CC6.6"],
                ],
            },
            
            # Dangerous Tools Exposed (MCP-AUTHZ-001)
            "MCP-AUTHZ-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.9.4.1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["AC-3"],
                    NIST_800_53_CONTROLS["AC-6"],
                ],
                ComplianceFramework.SOC2: [
                    SOC2_CONTROLS["CC6.1"],
                ],
            },
            
            # CORS Misconfiguration (MCP-CORS-001, MCP-CORS-002, MCP-CORS-003)
            "MCP-CORS-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["AC-3"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1189"],
                ],
            },
            "MCP-CORS-002": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["AC-3"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1189"],
                ],
            },
            "MCP-CORS-003": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["AC-3"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1189"],
                ],
            },
            
            # No Rate Limiting (MCP-RATE-001, MCP-RATE-002)
            "MCP-RATE-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.12.2.1"],
                    ISO27001_CONTROLS["A.17.2.1"],
                ],
                ComplianceFramework.NIST_CSF: [
                    NIST_CSF_CONTROLS["DE.AE-5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SC-5"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1499"],
                ],
                ComplianceFramework.SOC2: [
                    SOC2_CONTROLS["CC7.2"],
                ],
            },
            "MCP-RATE-002": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.12.2.1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SC-5"],
                ],
            },
            
            # SQL Injection (MCP-INJ-001, MCP-INJ-002)
            "MCP-INJ-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.1"],
                    ISO27001_CONTROLS["A.12.6.1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SI-10"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1190"],
                ],
                ComplianceFramework.PCI_DSS: [
                    PCI_DSS_CONTROLS["6.5.1"],
                ],
            },
            "MCP-INJ-002": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SI-10"],
                ],
                ComplianceFramework.PCI_DSS: [
                    PCI_DSS_CONTROLS["6.5.1"],
                ],
            },
            
            # Command Injection (MCP-INJ-003, MCP-INJ-004)
            "MCP-INJ-003": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SI-10"],
                    NIST_800_53_CONTROLS["CM-7"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1059"],
                ],
                ComplianceFramework.PCI_DSS: [
                    PCI_DSS_CONTROLS["6.5.1"],
                ],
            },
            "MCP-INJ-004": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["SI-10"],
                ],
            },
            
            # Path Traversal (MCP-INJ-005, MCP-INJ-006)
            "MCP-INJ-005": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.9.4.1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["AC-6"],
                    NIST_800_53_CONTROLS["SI-10"],
                ],
                ComplianceFramework.MITRE_ATTCK: [
                    MITRE_ATTCK_TECHNIQUES["T1083"],
                ],
                ComplianceFramework.PCI_DSS: [
                    PCI_DSS_CONTROLS["6.5.1"],
                ],
            },
            "MCP-INJ-006": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.9.4.1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["AC-6"],
                ],
            },
            
            # Default Port Configuration (MCP-CONFIG-001)
            "MCP-CONFIG-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.13.1.1"],
                ],
                ComplianceFramework.NIST_CSF: [
                    NIST_CSF_CONTROLS["PR.IP-1"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["CM-7"],
                ],
            },
            
            # Version Information Disclosure (MCP-INFO-001)
            "MCP-INFO-001": {
                ComplianceFramework.ISO27001: [
                    ISO27001_CONTROLS["A.14.2.5"],
                ],
                ComplianceFramework.NIST_800_53: [
                    NIST_800_53_CONTROLS["CM-7"],
                ],
            },
        }
    
    def get_controls(
        self,
        vuln_id: str,
        framework: Optional[ComplianceFramework] = None
    ) -> List[FrameworkControl]:
        """
        Get compliance controls for a vulnerability
        
        Args:
            vuln_id: Vulnerability ID
            framework: Optional specific framework to filter by
            
        Returns:
            List of relevant controls
        """
        if vuln_id not in self.mappings:
            logger.debug(f"No compliance mappings found for {vuln_id}")
            return []
        
        if framework:
            return self.mappings[vuln_id].get(framework, [])
        
        # Return all controls for all frameworks
        all_controls = []
        for controls_list in self.mappings[vuln_id].values():
            all_controls.extend(controls_list)
        return all_controls
    
    def get_frameworks(self, vuln_id: str) -> Set[ComplianceFramework]:
        """Get all frameworks relevant to a vulnerability"""
        if vuln_id not in self.mappings:
            return set()
        return set(self.mappings[vuln_id].keys())
    
    def get_compliance_summary(
        self,
        vulnerabilities: List[Dict]
    ) -> Dict[ComplianceFramework, Dict]:
        """
        Get compliance summary across all frameworks
        
        Args:
            vulnerabilities: List of vulnerability dicts
            
        Returns:
            Dictionary with compliance status per framework
        """
        summary = {}
        
        for framework in ComplianceFramework:
            affected_controls = set()
            critical_count = 0
            high_count = 0
            
            for vuln in vulnerabilities:
                vuln_id = vuln.get('id', '')
                severity = vuln.get('severity', 'INFO')
                
                controls = self.get_controls(vuln_id, framework)
                affected_controls.update(controls)
                
                if severity == 'CRITICAL':
                    critical_count += 1
                elif severity == 'HIGH':
                    high_count += 1
            
            if affected_controls:
                summary[framework] = {
                    'affected_control_count': len(affected_controls),
                    'affected_controls': [c.to_dict() for c in affected_controls],
                    'critical_vulns': critical_count,
                    'high_vulns': high_count,
                    'compliance_status': 'NON_COMPLIANT'
                }
        
        return summary
    
    def get_framework_gap_analysis(
        self,
        vulnerabilities: List[Dict],
        framework: ComplianceFramework
    ) -> Dict:
        """
        Detailed gap analysis for a specific framework
        
        Args:
            vulnerabilities: List of vulnerability dicts
            framework: Framework to analyze
            
        Returns:
            Detailed gap analysis
        """
        affected_controls = set()
        vuln_by_category = {}
        control_to_vulns = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', '')
            vuln_title = vuln.get('title', 'Unknown')
            controls = self.get_controls(vuln_id, framework)
            
            for control in controls:
                affected_controls.add(control)
                category = control.category
                vuln_by_category[category] = vuln_by_category.get(category, 0) + 1
                
                if control.id not in control_to_vulns:
                    control_to_vulns[control.id] = []
                control_to_vulns[control.id].append({
                    'id': vuln_id,
                    'title': vuln_title,
                    'severity': vuln.get('severity', 'INFO')
                })
        
        return {
            'framework': framework.value,
            'framework_name': self._get_framework_name(framework),
            'total_affected_controls': len(affected_controls),
            'affected_controls': [c.to_dict() for c in sorted(affected_controls, key=lambda x: x.id)],
            'vulnerabilities_by_category': vuln_by_category,
            'control_to_vulnerabilities': control_to_vulns,
            'compliance_status': 'NON_COMPLIANT' if affected_controls else 'COMPLIANT',
            'risk_level': self._calculate_risk_level(len(affected_controls))
        }
    
    def _get_framework_name(self, framework: ComplianceFramework) -> str:
        """Get human-readable framework name"""
        names = {
            ComplianceFramework.ISO27001: "ISO/IEC 27001:2013",
            ComplianceFramework.NIST_CSF: "NIST Cybersecurity Framework",
            ComplianceFramework.NIST_800_53: "NIST SP 800-53 Rev. 5",
            ComplianceFramework.MITRE_ATTCK: "MITRE ATT&CK Framework",
            ComplianceFramework.PCI_DSS: "PCI DSS 3.2.1",
            ComplianceFramework.SOC2: "SOC 2 Type II",
            ComplianceFramework.GDPR: "GDPR",
            ComplianceFramework.HIPAA: "HIPAA",
        }
        return names.get(framework, framework.value)
    
    def _calculate_risk_level(self, affected_control_count: int) -> str:
        """Calculate risk level based on affected controls"""
        if affected_control_count >= 10:
            return "CRITICAL"
        elif affected_control_count >= 5:
            return "HIGH"
        elif affected_control_count >= 3:
            return "MEDIUM"
        elif affected_control_count >= 1:
            return "LOW"
        else:
            return "NONE"
