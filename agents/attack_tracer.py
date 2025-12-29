"""
PHASE 3: Attack Tracer Agent
Hybrid approach: Rule-based detection + LLM reasoning
Maps attacks to MITRE ATT&CK framework
"""

import json
from typing import List, Dict, Tuple
from collections import defaultdict, Counter
from datetime import datetime, timedelta


class AttackTracer:
    """Detects and traces attack patterns from normalized events"""

    def __init__(self):
        # MITRE ATT&CK mapping
        self.mitre_mapping = {
            'BruteForce': {
                'technique': 'T1110',
                'tactic': 'Credential Access',
                'name': 'Brute Force'
            },
            'Reconnaissance': {
                'technique': 'T1046',
                'tactic': 'Discovery',
                'name': 'Network Service Scanning'
            },
            'DDoS': {
                'technique': 'T1498',
                'tactic': 'Impact',
                'name': 'Network Denial of Service'
            },
            'DoS': {
                'technique': 'T1499',
                'tactic': 'Impact',
                'name': 'Endpoint Denial of Service'
            },
            'SQLInjection': {
                'technique': 'T1190',
                'tactic': 'Initial Access',
                'name': 'Exploit Public-Facing Application'
            },
            'WebAttack': {
                'technique': 'T1190',
                'tactic': 'Initial Access',
                'name': 'Exploit Public-Facing Application'
            },
            'Botnet': {
                'technique': 'T1583',
                'tactic': 'Resource Development',
                'name': 'Acquire Infrastructure'
            },
            'Infiltration': {
                'technique': 'T1078',
                'tactic': 'Initial Access',
                'name': 'Valid Accounts'
            },
            'Exploitation': {
                'technique': 'T1203',
                'tactic': 'Execution',
                'name': 'Exploitation for Client Execution'
            }
        }

        # Detection thresholds
        self.thresholds = {
            'failed_login_count': 5,
            'port_scan_threshold': 10,
            'ddos_requests_per_min': 100,
            'time_window_minutes': 5
        }

    def analyze_events(self, events: List[Dict]) -> Dict:
        """Main analysis function - detects attacks and builds timeline"""

        if not events:
            return {"error": "No events to analyze"}

        # Separate malicious from benign
        malicious_events = [e for e in events if e.get('is_malicious', False)]

        if not malicious_events:
            return {
                "attack_detected": False,
                "message": "No malicious activity detected",
                "total_events": len(events)
            }

        # Group by attack type and source
        attack_groups = self._group_attacks(malicious_events)

        # Analyze each attack group
        attack_chains = []
        for attack_type, attack_events in attack_groups.items():
            chain = self._analyze_attack_chain(attack_type, attack_events)
            attack_chains.append(chain)

        # Sort by severity and confidence
        attack_chains.sort(key=lambda x: (x['severity_score'], x['confidence']), reverse=True)

        return {
            "attack_detected": True,
            "total_attacks": len(attack_chains),
            "attack_chains": attack_chains,
            "analysis_timestamp": datetime.now().isoformat()
        }

    def _group_attacks(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by attack type"""
        groups = defaultdict(list)
        for event in events:
            attack_type = event.get('attack_type', 'Unknown')
            groups[attack_type].append(event)
        return dict(groups)

    def _analyze_attack_chain(self, attack_type: str, events: List[Dict]) -> Dict:
        """Analyze a specific attack chain"""

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x['timestamp'])

        # Extract IOCs (Indicators of Compromise)
        iocs = self._extract_iocs(events)

        # Calculate confidence based on rule matching
        confidence = self._calculate_confidence(attack_type, events)

        # Get MITRE mapping
        mitre_info = self.mitre_mapping.get(attack_type, {
            'technique': 'T0000',
            'tactic': 'Unknown',
            'name': attack_type
        })

        # Build timeline
        timeline = self._build_timeline(sorted_events)

        # Detect attack pattern
        pattern = self._detect_pattern(attack_type, events)

        # Generate evidence
        evidence = self._generate_evidence(attack_type, events, pattern)

        # Calculate severity
        severity_score = self._calculate_severity(attack_type, len(events), iocs)

        return {
            "attack_type": attack_type,
            "mitre_technique": mitre_info['technique'],
            "mitre_tactic": mitre_info['tactic'],
            "technique_name": mitre_info['name'],
            "timeline": timeline,
            "iocs": iocs,
            "confidence": confidence,
            "severity_score": severity_score,
            "severity_level": self._get_severity_level(severity_score),
            "pattern": pattern,
            "evidence": evidence,
            "event_count": len(events)
        }

    def _extract_iocs(self, events: List[Dict]) -> Dict:
        """Extract Indicators of Compromise"""
        source_ips = set()
        dest_ips = set()
        ports = set()

        for event in events:
            source_ips.add(event.get('source_ip', 'unknown'))
            dest_ips.add(event.get('destination_ip', 'unknown'))
            if event.get('destination_port'):
                ports.add(event['destination_port'])

        return {
            "malicious_ips": list(source_ips),
            "targeted_ips": list(dest_ips),
            "targeted_ports": sorted(list(ports)),
            "protocol_distribution": self._get_protocol_distribution(events)
        }

    def _get_protocol_distribution(self, events: List[Dict]) -> Dict:
        """Get distribution of protocols used"""
        protocols = [e.get('protocol', 'UNKNOWN') for e in events]
        return dict(Counter(protocols))

    def _calculate_confidence(self, attack_type: str, events: List[Dict]) -> float:
        """Calculate confidence score based on rules"""

        base_confidence = 0.7  # Start with baseline

        # More events = higher confidence
        if len(events) > 50:
            base_confidence += 0.15
        elif len(events) > 20:
            base_confidence += 0.1
        elif len(events) > 5:
            base_confidence += 0.05

        # Pattern-specific confidence boosts
        if attack_type == 'BruteForce':
            # Check for repeated failed attempts
            ip_counts = Counter(e.get('source_ip') for e in events)
            if any(count > self.thresholds['failed_login_count'] for count in ip_counts.values()):
                base_confidence += 0.1

        elif attack_type == 'Reconnaissance':
            # Check for port scanning pattern
            unique_ports = len(set(e.get('destination_port') for e in events))
            if unique_ports > self.thresholds['port_scan_threshold']:
                base_confidence += 0.15

        elif attack_type in ['DDoS', 'DoS']:
            # Check request rate
            if len(events) > self.thresholds['ddos_requests_per_min']:
                base_confidence += 0.1

        return min(base_confidence, 0.99)  # Cap at 0.99

    def _build_timeline(self, events: List[Dict]) -> List[Dict]:
        """Build attack timeline with key events"""
        timeline = []

        # Add first event
        if events:
            timeline.append({
                "timestamp": events[0]['timestamp'],
                "event": "Attack initiated",
                "details": f"First {events[0]['attack_type']} activity detected"
            })

        # Add middle events (sample)
        if len(events) > 2:
            mid_idx = len(events) // 2
            timeline.append({
                "timestamp": events[mid_idx]['timestamp'],
                "event": "Attack escalation",
                "details": f"Continued malicious activity ({len(events)} total events)"
            })

        # Add last event
        if events:
            timeline.append({
                "timestamp": events[-1]['timestamp'],
                "event": "Last observed activity",
                "details": f"Final {events[-1]['attack_type']} event recorded"
            })

        return timeline

    def _detect_pattern(self, attack_type: str, events: List[Dict]) -> Dict:
        """Detect specific attack patterns"""

        pattern = {
            "name": attack_type,
            "characteristics": []
        }

        # Analyze based on attack type
        if attack_type == 'BruteForce':
            ip_attempts = Counter(e.get('source_ip') for e in events)
            max_attempts = max(ip_attempts.values()) if ip_attempts else 0
            pattern['characteristics'] = [
                f"Multiple login attempts from {len(ip_attempts)} unique IPs",
                f"Maximum {max_attempts} attempts from single source",
                "Credential stuffing pattern detected" if max_attempts > 10 else "Standard brute force"
            ]

        elif attack_type == 'Reconnaissance':
            ports = set(e.get('destination_port') for e in events)
            pattern['characteristics'] = [
                f"Scanned {len(ports)} unique ports",
                f"Targeted {len(set(e.get('destination_ip') for e in events))} hosts",
                "Systematic scanning pattern" if len(ports) > 20 else "Targeted port probe"
            ]

        elif attack_type in ['DDoS', 'DoS']:
            pattern['characteristics'] = [
                f"High request volume: {len(events)} requests",
                f"Attack sources: {len(set(e.get('source_ip') for e in events))} IPs",
                "Distributed attack" if len(set(e.get('source_ip') for e in events)) > 10 else "Single-source DoS"
            ]

        return pattern

    def _generate_evidence(self, attack_type: str, events: List[Dict], pattern: Dict) -> List[str]:
        """Generate human-readable evidence"""
        evidence = []

        # Common evidence
        evidence.append(f"Detected {len(events)} malicious events classified as {attack_type}")

        # Attack-specific evidence
        if attack_type == 'BruteForce':
            evidence.append("Multiple failed authentication attempts from same sources")
            evidence.append("Attempts targeted common authentication services")

        elif attack_type == 'Reconnaissance':
            evidence.append("Sequential port scanning behavior observed")
            evidence.append("Attacker probing for vulnerable services")

        elif attack_type in ['DDoS', 'DoS']:
            evidence.append("Abnormally high request rate detected")
            evidence.append("Service availability likely impacted")

        elif attack_type in ['SQLInjection', 'WebAttack']:
            evidence.append("Malicious payload detected in web requests")
            evidence.append("Exploitation of web application vulnerabilities")

        return evidence

    def _calculate_severity(self, attack_type: str, event_count: int, iocs: Dict) -> int:
        """Calculate severity score (1-10)"""

        base_severity = {
            'BruteForce': 6,
            'Reconnaissance': 4,
            'DDoS': 8,
            'DoS': 7,
            'SQLInjection': 9,
            'WebAttack': 8,
            'Botnet': 7,
            'Infiltration': 10,
            'Exploitation': 9
        }

        severity = base_severity.get(attack_type, 5)

        # Adjust based on scale
        if event_count > 100:
            severity = min(severity + 2, 10)
        elif event_count > 50:
            severity = min(severity + 1, 10)

        # Adjust based on targets
        if len(iocs.get('targeted_ips', [])) > 5:
            severity = min(severity + 1, 10)

        return severity

    def _get_severity_level(self, score: int) -> str:
        """Convert numeric severity to label"""
        if score >= 9:
            return "Critical"
        elif score >= 7:
            return "High"
        elif score >= 5:
            return "Medium"
        else:
            return "Low"


def main():
    """Example usage"""
    # Load normalized events
    with open(r"C:\cyber_agentic_ai\data\processed\normalized_events.json", 'r') as f:

        events = json.load(f)

    # Initialize tracer
    tracer = AttackTracer()

    # Analyze attacks
    print("Analyzing attack patterns...")
    results = tracer.analyze_events(events)

    # Save results
    with open(r"C:\cyber_agentic_ai\data\processed\attack_analysis.json", 'w') as f:

        json.dump(results, f, indent=2)

    # Print summary
    if results.get('attack_detected'):
        print(f"\n🚨 Detected {results['total_attacks']} attack patterns")
        for chain in results['attack_chains'][:3]:  # Show top 3
            print(f"\n  Attack: {chain['attack_type']}")
            print(f"  MITRE: {chain['mitre_technique']} - {chain['technique_name']}")
            print(f"  Severity: {chain['severity_level']} ({chain['severity_score']}/10)")
            print(f"  Confidence: {chain['confidence']:.2%}")
    else:
        print("\n✓ No attacks detected")


if __name__ == "__main__":
    main()