"""
PHASE 4: Impact Analyst Agent
Assesses business impact, financial loss, and compliance risks
"""
from pathlib import Path
import json
from typing import Dict, List
from datetime import datetime, timedelta




class ImpactAnalyst:
    """Analyzes business impact of detected attacks"""

    def __init__(self):
        # Asset criticality mapping
        self.asset_criticality = {
            'database': {'criticality': 10, 'name': 'Database Server'},
            'web': {'criticality': 8, 'name': 'Web Server'},
            'auth': {'criticality': 9, 'name': 'Authentication Server'},
            'file': {'criticality': 7, 'name': 'File Server'},
            'dns': {'criticality': 9, 'name': 'DNS Server'},
            'mail': {'criticality': 7, 'name': 'Mail Server'},
            'backup': {'criticality': 8, 'name': 'Backup Server'}
        }

        # Cost estimates per hour of downtime
        self.downtime_cost_per_hour = {
            'Critical': 50000,
            'High': 25000,
            'Medium': 10000,
            'Low': 2000
        }

        # Compliance frameworks affected
        self.compliance_frameworks = {
            'data_breach': ['GDPR', 'CCPA', 'HIPAA'],
            'authentication': ['PCI-DSS', 'SOX', 'ISO 27001'],
            'availability': ['ISO 27001', 'SOC 2'],
            'web_attack': ['OWASP', 'PCI-DSS']
        }

    def analyze_impact(self, attack_analysis: Dict) -> Dict:
        """Main impact analysis function"""

        if not attack_analysis.get('attack_detected'):
            return {
                "impact_detected": False,
                "message": "No attacks to analyze"
            }

        attack_chains = attack_analysis.get('attack_chains', [])

        # Analyze each attack chain
        impact_assessments = []
        total_estimated_loss = 0

        for chain in attack_chains:
            impact = self._assess_attack_impact(chain)
            impact_assessments.append(impact)
            total_estimated_loss += impact['estimated_loss_usd']

        # Aggregate overall impact
        overall_impact = self._aggregate_impact(impact_assessments)
        overall_impact['total_estimated_loss_usd'] = total_estimated_loss
        overall_impact['individual_impacts'] = impact_assessments
        overall_impact['analysis_timestamp'] = datetime.now().isoformat()

        return overall_impact

    def _assess_attack_impact(self, attack_chain: Dict) -> Dict:
        """Assess impact for a single attack chain"""

        attack_type = attack_chain['attack_type']
        severity_level = attack_chain['severity_level']
        event_count = attack_chain['event_count']
        iocs = attack_chain.get('iocs', {})

        # Identify affected assets
        affected_assets = self._identify_affected_assets(attack_type, iocs)

        # Estimate downtime
        downtime_hours = self._estimate_downtime(attack_type, severity_level, event_count)

        # Calculate financial loss
        financial_loss = self._calculate_financial_loss(
            severity_level,
            downtime_hours,
            affected_assets
        )

        # Assess data risk
        data_risk = self._assess_data_risk(attack_type, affected_assets)

        # Identify compliance impacts
        compliance_risks = self._identify_compliance_risks(attack_type, data_risk)

        # Calculate reputation impact
        reputation_impact = self._assess_reputation_impact(
            attack_type,
            severity_level,
            data_risk['data_at_risk']
        )

        # Generate recovery time estimate
        recovery_time = self._estimate_recovery_time(attack_type, severity_level)

        return {
            "attack_type": attack_type,
            "severity": severity_level,
            "affected_assets": affected_assets,
            "downtime_hours": downtime_hours,
            "estimated_loss_usd": financial_loss,
            "data_risk": data_risk,
            "compliance_risks": compliance_risks,
            "reputation_impact": reputation_impact,
            "recovery_estimate": recovery_time,
            "business_impact_score": self._calculate_business_impact_score(
                financial_loss,
                len(affected_assets),
                data_risk['risk_level']
            )
        }

    def _identify_affected_assets(self, attack_type: str, iocs: Dict) -> List[Dict]:
        """Identify which assets are affected"""

        affected = []
        targeted_ips = iocs.get('targeted_ips', [])
        targeted_ports = iocs.get('targeted_ports', [])

        # Map ports to services/assets
        port_mapping = {
            22: 'auth',  # SSH
            21: 'file',  # FTP
            80: 'web',  # HTTP
            443: 'web',  # HTTPS
            3306: 'database',  # MySQL
            5432: 'database',  # PostgreSQL
            1433: 'database',  # MSSQL
            53: 'dns',  # DNS
            25: 'mail',  # SMTP
            587: 'mail',  # SMTP
        }

        # Identify assets based on targeted ports
        asset_types = set()
        for port in targeted_ports:
            if port in port_mapping:
                asset_types.add(port_mapping[port])

        # Default assets based on attack type
        if attack_type in ['BruteForce']:
            asset_types.add('auth')
        elif attack_type in ['SQLInjection', 'WebAttack']:
            asset_types.add('database')
            asset_types.add('web')
        elif attack_type in ['DDoS', 'DoS']:
            asset_types.add('web')

        # Convert to asset details
        for asset_type in asset_types:
            if asset_type in self.asset_criticality:
                affected.append({
                    'type': asset_type,
                    'name': self.asset_criticality[asset_type]['name'],
                    'criticality': self.asset_criticality[asset_type]['criticality'],
                    'targeted_ips': targeted_ips[:3]  # Sample IPs
                })

        return affected if affected else [{
            'type': 'unknown',
            'name': 'Unknown System',
            'criticality': 5,
            'targeted_ips': targeted_ips[:3]
        }]

    def _estimate_downtime(self, attack_type: str, severity_level: str, event_count: int) -> float:
        """Estimate downtime in hours"""

        base_downtime = {
            'Critical': 8.0,
            'High': 4.0,
            'Medium': 2.0,
            'Low': 0.5
        }

        downtime = base_downtime.get(severity_level, 1.0)

        # Adjust based on attack type
        if attack_type in ['DDoS', 'DoS', 'Infiltration']:
            downtime *= 1.5  # These cause immediate service disruption
        elif attack_type in ['Reconnaissance']:
            downtime *= 0.2  # Minimal direct impact

        # Adjust based on attack scale
        if event_count > 1000:
            downtime *= 1.3
        elif event_count > 500:
            downtime *= 1.15

        return round(downtime, 2)

    def _calculate_financial_loss(self, severity_level: str, downtime_hours: float,
                                  affected_assets: List[Dict]) -> int:
        """Calculate estimated financial loss"""

        # Base downtime cost
        hourly_cost = self.downtime_cost_per_hour.get(severity_level, 5000)
        downtime_loss = int(hourly_cost * downtime_hours)

        # Asset criticality multiplier
        if affected_assets:
            max_criticality = max(asset['criticality'] for asset in affected_assets)
            criticality_multiplier = max_criticality / 10
            downtime_loss = int(downtime_loss * criticality_multiplier)

        # Additional costs
        incident_response_cost = 5000  # Base IR cost
        investigation_cost = 3000

        # Recovery costs based on asset count
        recovery_cost = len(affected_assets) * 2000

        total_loss = downtime_loss + incident_response_cost + investigation_cost + recovery_cost

        return total_loss

    def _assess_data_risk(self, attack_type: str, affected_assets: List[Dict]) -> Dict:
        """Assess risk to data confidentiality, integrity, availability"""

        risk_assessment = {
            'confidentiality': 'Low',
            'integrity': 'Low',
            'availability': 'Low',
            'data_at_risk': 'None'
        }

        # Assess based on attack type
        if attack_type == 'SQLInjection':
            risk_assessment['confidentiality'] = 'Critical'
            risk_assessment['integrity'] = 'High'
            risk_assessment['data_at_risk'] = 'Database records, PII, credentials'

        elif attack_type == 'BruteForce':
            risk_assessment['confidentiality'] = 'High'
            risk_assessment['data_at_risk'] = 'User credentials, authentication tokens'

        elif attack_type in ['DDoS', 'DoS']:
            risk_assessment['availability'] = 'Critical'
            risk_assessment['data_at_risk'] = 'Service availability'

        elif attack_type == 'Infiltration':
            risk_assessment['confidentiality'] = 'Critical'
            risk_assessment['integrity'] = 'High'
            risk_assessment['availability'] = 'Medium'
            risk_assessment['data_at_risk'] = 'Sensitive business data, intellectual property'

        elif attack_type == 'Reconnaissance':
            risk_assessment['confidentiality'] = 'Low'
            risk_assessment['data_at_risk'] = 'Network topology information'

        # Adjust based on affected assets
        for asset in affected_assets:
            if asset['type'] == 'database':
                risk_assessment['confidentiality'] = 'Critical'
                risk_assessment['data_at_risk'] = 'Database records, PII'
            elif asset['type'] == 'auth':
                risk_assessment['confidentiality'] = 'High'

        # Calculate overall risk level
        risk_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        max_risk = max(
            risk_levels.get(risk_assessment['confidentiality'], 1),
            risk_levels.get(risk_assessment['integrity'], 1),
            risk_levels.get(risk_assessment['availability'], 1)
        )

        risk_labels = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        risk_assessment['risk_level'] = risk_labels[max_risk]

        return risk_assessment

    def _identify_compliance_risks(self, attack_type: str, data_risk: Dict) -> List[Dict]:
        """Identify compliance framework violations"""

        risks = []

        # Map attack to compliance concerns
        if data_risk['risk_level'] in ['High', 'Critical']:
            if 'PII' in data_risk['data_at_risk'] or 'credentials' in data_risk['data_at_risk']:
                risks.append({
                    'framework': 'GDPR',
                    'risk': 'Personal data breach',
                    'potential_fine': 'Up to €20M or 4% of revenue',
                    'notification_required': True,
                    'deadline_hours': 72
                })
                risks.append({
                    'framework': 'CCPA',
                    'risk': 'Consumer data compromise',
                    'potential_fine': 'Up to $7,500 per violation',
                    'notification_required': True,
                    'deadline_hours': 48
                })

        if attack_type in ['SQLInjection', 'WebAttack', 'BruteForce']:
            risks.append({
                'framework': 'PCI-DSS',
                'risk': 'Inadequate security controls',
                'potential_fine': 'Loss of card processing privileges',
                'notification_required': True,
                'deadline_hours': 24
            })

        if data_risk['availability'] in ['High', 'Critical']:
            risks.append({
                'framework': 'ISO 27001',
                'risk': 'Availability breach',
                'potential_fine': 'Certification loss',
                'notification_required': False,
                'deadline_hours': None
            })

        return risks

    def _assess_reputation_impact(self, attack_type: str, severity_level: str,
                                  data_at_risk: str) -> Dict:
        """Assess impact on company reputation"""

        impact_score = 0

        # Base impact by severity
        severity_impact = {'Critical': 8, 'High': 6, 'Medium': 4, 'Low': 2}
        impact_score = severity_impact.get(severity_level, 3)

        # Increase for data breaches
        if 'PII' in data_at_risk or 'credentials' in data_at_risk:
            impact_score = min(impact_score + 2, 10)

        # Public visibility
        public_impact = attack_type in ['DDoS', 'DoS', 'Infiltration', 'SQLInjection']

        impact_levels = {
            (0, 3): 'Minimal',
            (3, 5): 'Low',
            (5, 7): 'Moderate',
            (7, 9): 'Significant',
            (9, 11): 'Severe'
        }

        impact_label = 'Minimal'
        for (low, high), label in impact_levels.items():
            if low <= impact_score < high:
                impact_label = label
                break

        return {
            'impact_score': impact_score,
            'impact_level': impact_label,
            'public_visibility': 'High' if public_impact else 'Low',
            'customer_impact': 'Direct' if public_impact else 'Indirect',
            'media_risk': 'High' if impact_score >= 7 else 'Medium' if impact_score >= 5 else 'Low'
        }

    def _estimate_recovery_time(self, attack_type: str, severity_level: str) -> Dict:
        """Estimate recovery timeline"""

        base_times = {
            'Critical': {'hours': 24, 'days': 7},
            'High': {'hours': 12, 'days': 3},
            'Medium': {'hours': 4, 'days': 1},
            'Low': {'hours': 2, 'days': 0.5}
        }

        time_estimate = base_times.get(severity_level, {'hours': 4, 'days': 1})

        return {
            'immediate_containment_hours': time_estimate['hours'],
            'full_recovery_days': time_estimate['days'],
            'phases': [
                'Immediate containment and isolation',
                'Threat eradication and system hardening',
                'Service restoration and validation',
                'Post-incident review and improvements'
            ]
        }

    def _calculate_business_impact_score(self, financial_loss: int,
                                         asset_count: int, risk_level: str) -> int:
        """Calculate overall business impact score (1-10)"""

        score = 0

        # Financial component (0-4 points)
        if financial_loss > 100000:
            score += 4
        elif financial_loss > 50000:
            score += 3
        elif financial_loss > 20000:
            score += 2
        else:
            score += 1

        # Asset component (0-3 points)
        score += min(asset_count, 3)

        # Risk component (0-3 points)
        risk_scores = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 3}
        score += risk_scores.get(risk_level, 1)

        return min(score, 10)

    def _aggregate_impact(self, impact_assessments: List[Dict]) -> Dict:
        """Aggregate impact across all attacks"""

        if not impact_assessments:
            return {"impact_detected": False}

        # Find highest severity
        severities = [a['severity'] for a in impact_assessments]
        severity_order = ['Low', 'Medium', 'High', 'Critical']
        max_severity = max(severities, key=lambda x: severity_order.index(x))

        # Aggregate unique assets
        all_assets = []
        for assessment in impact_assessments:
            all_assets.extend(assessment['affected_assets'])

        unique_assets = list({asset['name']: asset for asset in all_assets}.values())

        # Aggregate compliance risks
        all_compliance = []
        for assessment in impact_assessments:
            all_compliance.extend(assessment['compliance_risks'])

        unique_compliance = list({risk['framework']: risk for risk in all_compliance}.values())

        return {
            "impact_detected": True,
            "overall_severity": max_severity,
            "total_affected_assets": len(unique_assets),
            "affected_asset_summary": unique_assets,
            "compliance_violations": unique_compliance,
            "requires_notification": any(r.get('notification_required') for r in all_compliance),
            "critical_actions_required": len([a for a in impact_assessments if a['severity'] in ['High', 'Critical']])
        }


def main():
    """Example usage"""
    # Load attack analysis results
    attack_analysis_path = r"C:\cyber_agentic_ai\data\processed\attack_analysis.json"
    with open(attack_analysis_path, 'r') as f:
        attack_analysis = json.load(f)

    # Initialize analyst
    analyst = ImpactAnalyst()

    # Analyze impact
    print("Analyzing business impact...")
    impact_results = analyst.analyze_impact(attack_analysis)

    # Save results
    output_path = Path("data/processed/impact_analysis.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Create directory if missing

    with open(output_path, 'w') as f:
        json.dump(impact_results, f, indent=2)

    # Print summary
    if impact_results.get('impact_detected'):
        print(f"\n💰 Total Estimated Loss: ${impact_results['total_estimated_loss_usd']:,}")
        print(f"🎯 Affected Assets: {impact_results['total_affected_assets']}")
        print(f"⚠️  Overall Severity: {impact_results['overall_severity']}")
        if impact_results['requires_notification']:
            print(f"📢 Compliance Notification Required")
    else:
        print("\n✓ No significant impact detected")


if __name__ == "__main__":
    main()