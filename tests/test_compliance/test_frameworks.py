"""
Tests for Framework Definitions
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from compliance.frameworks import (
    ComplianceFramework,
    FrameworkControl,
    ISO27001_CONTROLS,
    NIST_CSF_CONTROLS,
    NIST_800_53_CONTROLS,
    MITRE_ATTCK_TECHNIQUES,
)


def test_framework_enum():
    """Test framework enum values"""
    assert ComplianceFramework.ISO27001.value == "ISO27001"
    assert ComplianceFramework.NIST_CSF.value == "NIST_CSF"
    assert ComplianceFramework.MITRE_ATTCK.value == "MITRE_ATTCK"


def test_framework_control_dataclass():
    """Test FrameworkControl dataclass"""
    control = FrameworkControl(
        id="A.9.2.1",
        name="Test Control",
        description="Test description",
        framework=ComplianceFramework.ISO27001,
        category="Access Control"
    )
    
    assert control.id == "A.9.2.1"
    assert control.framework == ComplianceFramework.ISO27001
    assert control.category == "Access Control"


def test_iso27001_controls():
    """Test ISO 27001 controls are defined"""
    assert len(ISO27001_CONTROLS) > 0
    assert "A.9.2.1" in ISO27001_CONTROLS
    assert "A.10.1.1" in ISO27001_CONTROLS
    
    control = ISO27001_CONTROLS["A.9.2.1"]
    assert control.framework == ComplianceFramework.ISO27001
    assert "User Registration" in control.name


def test_nist_csf_controls():
    """Test NIST CSF controls are defined"""
    assert len(NIST_CSF_CONTROLS) > 0
    assert "PR.AC-1" in NIST_CSF_CONTROLS
    
    control = NIST_CSF_CONTROLS["PR.AC-1"]
    assert control.framework == ComplianceFramework.NIST_CSF


def test_nist_800_53_controls():
    """Test NIST 800-53 controls are defined"""
    assert len(NIST_800_53_CONTROLS) > 0
    assert "IA-2" in NIST_800_53_CONTROLS
    assert "AC-2" in NIST_800_53_CONTROLS


def test_mitre_attck_techniques():
    """Test MITRE ATT&CK techniques are defined"""
    assert len(MITRE_ATTCK_TECHNIQUES) > 0
    assert "T1078" in MITRE_ATTCK_TECHNIQUES
    
    technique = MITRE_ATTCK_TECHNIQUES["T1078"]
    assert technique.framework == ComplianceFramework.MITRE_ATTCK
    assert "Valid Accounts" in technique.name


def test_control_to_dict():
    """Test control conversion to dict"""
    control = ISO27001_CONTROLS["A.9.2.1"]
    control_dict = control.to_dict()
    
    assert isinstance(control_dict, dict)
    assert control_dict['id'] == "A.9.2.1"
    assert control_dict['framework'] == "ISO27001"
    assert 'name' in control_dict
    assert 'description' in control_dict
    assert 'category' in control_dict
