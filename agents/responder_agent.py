"""
PHASE 5: Responder Agent
Generates actionable incident response plans based on NIST framework
No hallucinations - only evidence-based best practices
"""
from pathlib import Path
import json
from typing import Dict, List
from datetime import datetime


class IncidentResponder:
    """Generates structured incident response plans"""

    def __init__(self):
        # NIST Incident Response phases
        self.response_phases = [
            'Containment',
            'Eradication',
            'Recovery',
            'Prevention'
        ]

        # Attack-specific response playbooks
        self.response_playbooks = {
            'BruteForce': {
                'containment': [
                    'Block source IP addresses at firewall',
                    'Temporarily disable compromised accounts',
                    'Enable account lockout after failed attempts',
                    'Implement rate limiting on authentication endpoints'
                ],
                'eradication': [
                    'Force password reset for all affected accounts',
                    'Revoke all active session tokens',
                    'Review and remove any unauthorized access grants',
                    'Scan for compromised credentials in breach databases'
                ],
                'recovery': [
                    'Enable affected user accounts with new credentials',
                    'Restore authentication service to normal operation',
                    'Monitor authentication logs for 48 hours',
                    'Notify affected users of security incident'
                ],
                'prevention': [
                    'Implement multi-factor authentication (MFA)',
                    'Deploy CAPTCHA on login forms',
                    'Set up anomaly detection for authentication attempts',
                    'Enforce strong password policies (min 12 characters)'
                ]
            },
            'Reconnaissance': {
                'containment': [
                    'Block scanning IP addresses',
                    'Enable aggressive firewall rules',
                    'Isolate honeypot systems if deployed',
                    'Alert security team of potential future attack'
                ],
                'eradication': [
                    'Review firewall logs for complete scan scope',
                    'Identify all probed services and ports',
                    'Document attack patterns and TTPs',
                    'Check for any successful exploitation attempts'
                ],
                'recovery': [
                    'Return firewall rules to normal state',
                    'Continue enhanced monitoring for 7 days',
                    'Update threat intelligence feeds',
                    'Brief security team on findings'
                ],
                'prevention': [
                    'Deploy network intrusion detection system (NIDS)',
                    'Implement port knocking for sensitive services',
                    'Reduce attack surface by closing unused ports',
                    'Deploy honeypots to detect reconnaissance'
                ]
            },
            'DDoS': {
                'containment': [
                    'Enable DDoS mitigation service (CloudFlare, AWS Shield)',
                    'Implement rate limiting at edge network',
                    'Block malicious ASNs and IP ranges',
                    'Scale infrastructure to handle increased load'
                ],
                'eradication': [
                    'Analyze traffic patterns to identify attack vectors',
                    'Work with ISP to implement upstream filtering',
                    'Identify and block botnet command servers',
                    'Document attack characteristics for future defense'
                ],
                'recovery': [
                    'Gradually restore normal traffic flow',
                    'Monitor service availability metrics',
                    'Restore CDN and caching configurations',
                    'Communicate service status to stakeholders'
                ],
                'prevention': [
                    'Deploy always-on DDoS protection',
                    'Implement geo-blocking if appropriate',
                    'Set up auto-scaling infrastructure',
                    'Create DDoS response runbook for future incidents'
                ]
            },
            'DoS': {
                'containment': [
                    'Block attacking IP address',
                    'Implement connection limits per IP',
                    'Enable SYN cookie protection',
                    'Restart affected services if unresponsive'
                ],
                'eradication': [
                    'Clear connection tables and caches',
                    'Identify vulnerability being exploited',
                    'Patch application if specific vulnerability found',
                    'Remove any malicious cron jobs or persistence'
                ],
                'recovery': [
                    'Restore service to full capacity',
                    'Monitor resource utilization closely',
                    'Verify all services functioning normally',
                    'Update incident documentation'
                ],
                'prevention': [
                    'Implement resource limits per connection',
                    'Deploy application firewall (WAF)',
                    'Set up service health monitoring',
                    'Create rate limiting policies'
                ]
            },
            'SQLInjection': {
                'containment': [
                    'Take vulnerable application offline immediately',
                    'Block attacker IP at WAF/firewall',
                    'Enable database query logging',
                    'Restrict database permissions to read-only if possible'
                ],
                'eradication': [
                    'Patch SQL injection vulnerability in code',
                    'Implement parameterized queries/prepared statements',
                    'Scan database for unauthorized changes',
                    'Remove any webshells or backdoors',
                    'Revoke compromised database credentials'
                ],
                'recovery': [
                    'Restore database from clean backup if compromised',
                    'Deploy patched application code',
                    'Run security regression tests',
                    'Monitor database audit logs for 30 days'
                ],
                'prevention': [
                    'Implement input validation and sanitization',
                    'Deploy Web Application Firewall (WAF)',
                    'Use ORM frameworks with built-in protection',
                    'Regular security code reviews and SAST scanning',
                    'Implement principle of least privilege for DB access'
                ]
            },
            'WebAttack': {
                'containment': [
                    'Block malicious requests at WAF',
                    'Disable vulnerable web application components',
                    'Enable verbose logging for forensics',
                    'Isolate affected web servers'
                ],
                'eradication': [
                    'Patch identified vulnerabilities',
                    'Remove malicious files uploaded by attacker',
                    'Clear web server caches',
                    'Scan for webshells and backdoors'
                ],
                'recovery': [
                    'Deploy hardened web application',
                    'Restore from known-good backups if needed',
                    'Update SSL/TLS certificates if compromised',
                    'Verify integrity of all web files'
                ],
                'prevention': [
                    'Deploy Web Application Firewall with OWASP rules',
                    'Implement Content Security Policy (CSP)',
                    'Regular vulnerability scanning (DAST)',
                    'Security awareness training for developers',
                    'Implement secure coding guidelines'
                ]
            },
            'Infiltration': {
                'containment': [
                    'Isolate compromised systems from network immediately',
                    'Disable compromised user accounts',
                    'Block all C2 (Command & Control) communications',
                    'Preserve forensic evidence (disk images, memory dumps)'
                ],
                'eradication': [
                    'Remove malware and persistence mechanisms',
                    'Rebuild compromised systems from clean media',
                    'Reset all credentials that may be compromised',
                    'Scan entire network for additional infections'
                ],
                'recovery': [
                    'Restore systems from verified clean backups',
                    'Gradually reconnect systems after validation',
                    'Re-enable user accounts with new credentials',
                    'Conduct organization-wide security review'
                ],
                'prevention': [
                    'Deploy EDR (Endpoint Detection & Response)',
                    'Implement network segmentation',
                    'Enable advanced threat protection',
                    'Regular security awareness training',
                    'Implement zero-trust architecture'
                ]
            },
            'Botnet': {
                'containment': [
                    'Isolate infected systems',
                    'Block C2 server communications',
                    'Monitor for lateral movement',
                    'Implement emergency network segmentation'
                ],
                'eradication': [
                    'Remove bot malware from infected systems',
                    'Patch vulnerabilities exploited for initial access',
                    'Clear all persistence mechanisms',
                    'Validate removal with multiple AV engines'
                ],
                'recovery': [
                    'Rebuild critically infected systems',
                    'Monitor network for reinfection signs',
                    'Restore normal network operations gradually',
                    'Update security baselines'
                ],
                'prevention': [
                    'Deploy next-gen antivirus/EDR',
                    'Implement application whitelisting',
                    'Block known C2 infrastructure',
                    'Regular malware scanning',
                    'Network traffic analysis for bot signatures'
                ]
            },
            'Exploitation': {
                'containment': [
                    'Isolate vulnerable systems immediately',
                    'Apply emergency patches if available',
                    'Block attack traffic at network perimeter',
                    'Enable enhanced monitoring on vulnerable services'
                ],
                'eradication': [
                    'Apply security patches to vulnerable software',
                    'Remove any implanted backdoors or malware',
                    'Review logs for full scope of compromise',
                    'Validate patches are correctly applied'
                ],
                'recovery': [
                    'Restore services with patched software',
                    'Verify system integrity',
                    'Resume normal operations with enhanced monitoring',
                    'Document exploitation method and patch'
                ],
                'prevention': [
                    'Implement automated patch management',
                    'Virtual patching via WAF/IPS where possible',
                    'Regular vulnerability assessments',
                    'Vulnerability disclosure monitoring',
                    'Defense-in-depth security controls'
                ]
            }
        }

    def generate_response_plan(self, attack_analysis: Dict, impact_analysis: Dict) -> Dict:
        """Generate comprehensive incident response plan"""

        if not attack_analysis.get('attack_detected'):
            return {
                "response_required": False,
                "message": "No incident detected"
            }

        attack_chains = attack_analysis.get('attack_chains', [])
        impact_assessments = impact_analysis.get('individual_impacts', [])

        # Generate response for each attack
        response_plans = []
        for i, chain in enumerate(attack_chains):
            impact = impact_assessments[i] if i < len(impact_assessments) else {}
            plan = self._generate_attack_response(chain, impact)
            response_plans.append(plan)

        # Create prioritized action list
        prioritized_actions = self._prioritize_actions(response_plans)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            attack_chains,
            impact_analysis,
            response_plans
        )

        return {
            "response_required": True,
            "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "severity": impact_analysis.get('overall_severity', 'Medium'),
            "executive_summary": executive_summary,
            "immediate_actions": prioritized_actions['immediate'],
            "short_term_actions": prioritized_actions['short_term'],
            "long_term_actions": prioritized_actions['long_term'],
            "detailed_response_plans": response_plans,
            "estimated_total_response_time_hours": self._estimate_total_response_time(response_plans),
            "recommended_team_size": self._recommend_team_size(impact_analysis),
            "notification_requirements": self._get_notification_requirements(impact_analysis),
            "generated_at": datetime.now().isoformat()
        }

    def _generate_attack_response(self, attack_chain: Dict, impact: Dict) -> Dict:
        """Generate response plan for specific attack"""

        attack_type = attack_chain['attack_type']
        severity = attack_chain['severity_level']

        # Get playbook or use generic response
        playbook = self.response_playbooks.get(attack_type, self._generic_playbook())

        return {
            "attack_type": attack_type,
            "attack_severity": severity,
            "mitre_technique": attack_chain['mitre_technique'],
            "containment": {
                "priority": "IMMEDIATE",
                "actions": playbook['containment'],
                "estimated_time_hours": 1
            },
            "eradication": {
                "priority": "HIGH",
                "actions": playbook['eradication'],
                "estimated_time_hours": 4
            },
            "recovery": {
                "priority": "MEDIUM",
                "actions": playbook['recovery'],
                "estimated_time_hours": 8
            },
            "prevention": {
                "priority": "ONGOING",
                "actions": playbook['prevention'],
                "estimated_time_hours": 40
            },
            "affected_assets": impact.get('affected_assets', []),
            "estimated_cost_usd": impact.get('estimated_loss_usd', 0)
        }

    def _generic_playbook(self) -> Dict:
        """Generic response playbook for unknown attack types"""
        return {
            'containment': [
                'Isolate affected systems',
                'Block malicious traffic',
                'Preserve forensic evidence',
                'Notify security team'
            ],
            'eradication': [
                'Identify and remove threat',
                'Patch vulnerabilities',
                'Reset compromised credentials',
                'Scan for additional infections'
            ],
            'recovery': [
                'Restore from backups if needed',
                'Verify system integrity',
                'Resume normal operations',
                'Continue enhanced monitoring'
            ],
            'prevention': [
                'Update security controls',
                'Implement lessons learned',
                'Conduct security training',
                'Review and update policies'
            ]
        }

    def _prioritize_actions(self, response_plans: List[Dict]) -> Dict:
        """Prioritize actions across all response plans"""

        immediate = []
        short_term = []
        long_term = []

        for plan in response_plans:
            attack_type = plan['attack_type']

            # Immediate actions (0-4 hours)
            for action in plan['containment']['actions']:
                immediate.append({
                    'action': action,
                    'attack_type': attack_type,
                    'phase': 'Containment'
                })

            # Short-term actions (4-24 hours)
            for action in plan['eradication']['actions']:
                short_term.append({
                    'action': action,
                    'attack_type': attack_type,
                    'phase': 'Eradication'
                })

            for action in plan['recovery']['actions']:
                short_term.append({
                    'action': action,
                    'attack_type': attack_type,
                    'phase': 'Recovery'
                })

            # Long-term actions (1-4 weeks)
            for action in plan['prevention']['actions']:
                long_term.append({
                    'action': action,
                    'attack_type': attack_type,
                    'phase': 'Prevention'
                })

        return {
            'immediate': immediate[:10],  # Top 10 immediate actions
            'short_term': short_term[:15],
            'long_term': long_term[:10]
        }

    def _generate_executive_summary(self, attack_chains: List[Dict],
                                    impact_analysis: Dict,
                                    response_plans: List[Dict]) -> str:
        """Generate executive summary of incident and response"""

        num_attacks = len(attack_chains)
        severity = impact_analysis.get('overall_severity', 'Unknown')
        total_loss = impact_analysis.get('total_estimated_loss_usd', 0)

        # Get primary attack types
        attack_types = [chain['attack_type'] for chain in attack_chains[:3]]
        attack_list = ', '.join(attack_types[:2])
        if len(attack_types) > 2:
            attack_list += f', and {attack_types[2]}'

        summary = f"""INCIDENT SUMMARY

Severity: {severity}
Estimated Financial Impact: ${total_loss:,} USD

Our systems have detected {num_attacks} distinct attack pattern(s), including {attack_list}. """

        if severity in ['Critical', 'High']:
            summary += f"""This is a {severity.lower()}-severity incident requiring immediate action. """

        if impact_analysis.get('requires_notification'):
            summary += """Regulatory notification is required within specified timeframes. """

        summary += f"""

RECOMMENDED ACTIONS:
1. Immediate containment measures have been identified
2. Eradication steps to remove threats from the environment
3. Recovery procedures to restore normal operations
4. Long-term prevention measures to avoid recurrence

Estimated total response time: {self._estimate_total_response_time(response_plans)} hours.
Recommended team size: {self._recommend_team_size(impact_analysis)} personnel.
"""

        return summary.strip()

    def _estimate_total_response_time(self, response_plans: List[Dict]) -> float:
        """Estimate total response time across all incidents"""

        total_hours = 0
        for plan in response_plans:
            total_hours += plan['containment']['estimated_time_hours']
            total_hours += plan['eradication']['estimated_time_hours']
            total_hours += plan['recovery']['estimated_time_hours']

        # Add parallelization factor (some work can be done concurrently)
        if len(response_plans) > 1:
            total_hours *= 0.7  # 30% time savings from parallel work

        return round(total_hours, 1)

    def _recommend_team_size(self, impact_analysis: Dict) -> int:
        """Recommend incident response team size"""

        severity = impact_analysis.get('overall_severity', 'Medium')
        num_assets = impact_analysis.get('total_affected_assets', 1)

        base_team = {
            'Critical': 6,
            'High': 4,
            'Medium': 2,
            'Low': 1
        }

        team_size = base_team.get(severity, 2)

        # Add personnel for large-scale incidents
        if num_assets > 10:
            team_size += 2
        elif num_assets > 5:
            team_size += 1

        return team_size

    def _get_notification_requirements(self, impact_analysis: Dict) -> List[Dict]:
        """Get regulatory and stakeholder notification requirements"""

        notifications = []

        # Regulatory notifications
        if impact_analysis.get('requires_notification'):
            for violation in impact_analysis.get('compliance_violations', []):
                if violation.get('notification_required'):
                    notifications.append({
                        'type': 'Regulatory',
                        'recipient': violation['framework'],
                        'deadline_hours': violation.get('deadline_hours'),
                        'priority': 'CRITICAL'
                    })

        # Internal notifications
        severity = impact_analysis.get('overall_severity')
        if severity in ['Critical', 'High']:
            notifications.extend([
                {
                    'type': 'Internal',
                    'recipient': 'Executive Leadership',
                    'deadline_hours': 2,
                    'priority': 'HIGH'
                },
                {
                    'type': 'Internal',
                    'recipient': 'Legal Department',
                    'deadline_hours': 4,
                    'priority': 'HIGH'
                }
            ])

        # Customer notifications
        if 'PII' in str(impact_analysis.get('individual_impacts', [])):
            notifications.append({
                'type': 'External',
                'recipient': 'Affected Customers',
                'deadline_hours': 48,
                'priority': 'HIGH'
            })

        return notifications


def main():
    # Base project directory (parent of agents folder)
    base_dir = Path(__file__).resolve().parent.parent  # C:\cyber_agentic_ai

    # Input files
    attack_file = base_dir / "data/processed/attack_analysis.json"
    impact_file = base_dir / "data/processed/impact_analysis.json"
    response_file = base_dir / "data/processed/response_plan.json"

    # Ensure input files exist
    if not attack_file.is_file():
        raise FileNotFoundError(f"Cannot find attack_analysis.json at {attack_file}")
    if not impact_file.is_file():
        raise FileNotFoundError(f"Cannot find impact_analysis.json at {impact_file}")

    # Load previous analysis results
    with open(attack_file, 'r') as f:
        attack_analysis = json.load(f)

    with open(impact_file, 'r') as f:
        impact_analysis = json.load(f)

    # Initialize responder
    responder = IncidentResponder()

    # Generate response plan
    print("Generating incident response plan...")
    response_plan = responder.generate_response_plan(attack_analysis, impact_analysis)

    # Make sure output directory exists
    response_file.parent.mkdir(parents=True, exist_ok=True)

    # Save results
    with open(response_file, 'w') as f:
        json.dump(response_plan, f, indent=2)

    # Print summary
    if response_plan.get('response_required'):
        print(f"\n📋 Incident ID: {response_plan['incident_id']}")
        print(f"⚠️  Severity: {response_plan['severity']}")
        print(f"\n{response_plan['executive_summary']}")
        print(f"\n🚨 Immediate Actions Required: {len(response_plan['immediate_actions'])}")
    else:
        print("\n✓ No response required")


if __name__ == "__main__":
    main()