"""
Scan report data model
Represents the results of a security scan
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from pydantic import BaseModel, Field

from .vulnerability import Vulnerability, Severity
from .server import MCPServer


class ScanReport(BaseModel):
    """Represents a complete scan report"""
    
    # Scan metadata
    scan_id: str = Field(description="Unique scan identifier")
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = Field(default=None)
    duration_seconds: Optional[float] = Field(default=None)
    
    # Target information
    target: Dict[str, Any] = Field(description="Scanned server")
    
    # Results
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Statistics
    total_checks: int = Field(default=0, description="Total checks performed")
    passed_checks: int = Field(default=0, description="Checks that passed")
    failed_checks: int = Field(default=0, description="Checks that failed")
    
    # Additional data
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "INFO")
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        }
        
        score = 0
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "INFO")
            score += weights.get(severity, 0)
        
        return min(score, 100)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return self.model_dump()
    
    def save_json(self, output_path: Path):
        """Save report as JSON"""
        import json
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
