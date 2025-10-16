"""
Tests for Compliance Mapper
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from compliance.mapper import ComplianceMapper
from compliance.frameworks import ComplianceFramework


def test_mapper_initialization():
    """Test mapper initializes correctly"""
    mapper = ComplianceMapper()
    assert mapper.mappings is not None
    assert len(mapper.mappings) > 0


def test_get_controls_for_auth_vuln():
    """Test getting controls for authentication vulnerability"""
    mapper = ComplianceMapper()
    controls = mapper.get_controls("MCP-AUTH-001")
    
    assert len(controls) > 0
    # Should have controls from multiple frameworks
    frameworks = {c.framework for c in controls}
    assert ComplianceFramework.ISO27001 in frameworks
    assert ComplianceFramework.NIST_CSF in frameworks


def test_get_controls_for_specific_framework():
    """Test getting controls for specific framework"""
    mapper = ComplianceMapper()
    controls = mapper.get_controls("MCP-AUTH-001", ComplianceFramework.ISO27001)
    
    assert len(controls) > 0
    assert all(c.framework == ComplianceFramework.ISO27001 for c in controls)


def test_get_frameworks_for_vulnerability():
    """Test getting applicable frameworks"""
    mapper = ComplianceMapper()
    frameworks = mapper.get_frameworks("MCP-AUTH-001")
    
    assert len(frameworks) > 0
    assert ComplianceFramework.ISO27001 in frameworks
    assert ComplianceFramework.NIST_CSF in frameworks


def test_compliance_summary():
    """Test compliance summary generation"""
    mapper = ComplianceMapper()
    
    vulnerabilities = [
        {
            'id': 'MCP-AUTH-001',
            'severity': 'CRITICAL',
            'title': 'Missing Authentication'
        },
        {
            'id': 'MCP-CRYPTO-001',
            'severity': 'HIGH',
            'title': 'Unencrypted Connection'
        }
    ]
    
    summary = mapper.get_compliance_summary(vulnerabilities)
    
    assert len(summary) > 0
    assert ComplianceFramework.ISO27001 in summary
    assert summary[ComplianceFramework.ISO27001]['compliance_status'] == 'NON_COMPLIANT'


def test_framework_gap_analysis():
    """Test detailed gap analysis"""
    mapper = ComplianceMapper()
    
    vulnerabilities = [
        {
            'id': 'MCP-AUTH-001',
            'severity': 'CRITICAL',
            'title': 'Missing Authentication'
        }
    ]
    
    gap_analysis = mapper.get_framework_gap_analysis(
        vulnerabilities,
        ComplianceFramework.ISO27001
    )
    
    assert gap_analysis['framework'] == 'ISO27001'
    assert gap_analysis['total_affected_controls'] > 0
    assert gap_analysis['compliance_status'] == 'NON_COMPLIANT'
    assert 'affected_controls' in gap_analysis


def test_unknown_vulnerability():
    """Test handling of unknown vulnerability ID"""
    mapper = ComplianceMapper()
    controls = mapper.get_controls("UNKNOWN-001")
    
    assert len(controls) == 0
    
    frameworks = mapper.get_frameworks("UNKNOWN-001")
    assert len(frameworks) == 0
