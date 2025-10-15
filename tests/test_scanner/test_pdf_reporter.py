"""
Tests for PDF report generation
"""

import pytest
from pathlib import Path
from src.models import MCPServer, Vulnerability, Severity
from src.scanner.pdf_reporter import PDFReportGenerator


def test_pdf_generator_initialization():
    """Test PDF generator can be initialized"""
    generator = PDFReportGenerator()
    assert generator is not None
    assert generator.styles is not None


def test_pdf_generation():
    """Test PDF report generation"""
    generator = PDFReportGenerator()
    
    # Create test data
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        name="Test Server"
    )
    
    vulnerabilities = [
        Vulnerability.create(
            id="TEST-001",
            title="Test Vulnerability",
            description="This is a test",
            severity=Severity.HIGH,
            category="Testing",
            remediation="Fix it",
            evidence=["Test evidence 1", "Test evidence 2"]
        )
    ]
    
    output_path = "reports/test_report.pdf"
    
    # Generate PDF
    result = generator.generate(server, vulnerabilities, output_path)
    
    # Check that file was created
    assert Path(result).exists()
    assert result.endswith('.pdf')
    
    # Cleanup
    Path(result).unlink()
