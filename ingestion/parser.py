"""
PHASE 2: Data Ingestion & Normalization for CICIDS2017
Converts raw CSV logs into unified JSON format for agent processing
"""

import pandas as pd
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict


class DataNormalizer:
    """Converts CICIDS2017 CSV data into unified event format"""

    def __init__(self):
        self.attack_type_mapping = {
            'BENIGN': 'Normal',
            'Bot': 'Botnet',
            'PortScan': 'Reconnaissance',
            'DDoS': 'DDoS',
            'FTP-Patator': 'BruteForce',
            'SSH-Patator': 'BruteForce',
            'DoS slowloris': 'DoS',
            'DoS Slowhttptest': 'DoS',
            'DoS Hulk': 'DoS',
            'DoS GoldenEye': 'DoS',
            'Heartbleed': 'Exploitation',
            'Web Attack – Brute Force': 'BruteForce',
            'Web Attack – XSS': 'WebAttack',
            'Web Attack – Sql Injection': 'SQLInjection',
            'Infiltration': 'Infiltration',
        }

    def normalize_cicids_event(self, row: pd.Series) -> Dict:
        """Convert a single CICIDS2017 row to normalized event"""

        # Extract basic fields
        timestamp = row.get('Timestamp', datetime.now().isoformat())
        src_ip = row.get('Source IP', row.get(' Source IP', 'unknown'))
        dst_ip = row.get('Destination IP', row.get(' Destination IP', 'unknown'))
        src_port = row.get('Source Port', row.get(' Source Port', 0))
        dst_port = row.get('Destination Port', row.get(' Destination Port', 0))
        protocol = row.get('Protocol', row.get(' Protocol', 'TCP'))

        # Get attack label
        label = row.get('Label', row.get(' Label', 'BENIGN'))
        attack_type = self.attack_type_mapping.get(label, 'Unknown')

        # Extract flow statistics
        flow_duration = row.get('Flow Duration', 0)
        total_fwd_packets = row.get('Total Fwd Packets', 0)
        total_bwd_packets = row.get('Total Backward Packets', 0)
        flow_bytes_per_s = row.get('Flow Bytes/s', 0)

        # Detect event type based on behavior
        event_type = self._determine_event_type(row, attack_type)

        return {
            "event_id": f"evt_{hash(str(row.to_dict()))}"[:16],
            "timestamp": str(timestamp),
            "source_ip": str(src_ip),
            "destination_ip": str(dst_ip),
            "source_port": int(src_port) if pd.notna(src_port) else 0,
            "destination_port": int(dst_port) if pd.notna(dst_port) else 0,
            "protocol": str(protocol).upper(),
            "event_type": event_type,
            "attack_type": attack_type,
            "label": label,
            "is_malicious": label != 'BENIGN',
            "flow_stats": {
                "duration": float(flow_duration) if pd.notna(flow_duration) else 0,
                "fwd_packets": int(total_fwd_packets) if pd.notna(total_fwd_packets) else 0,
                "bwd_packets": int(total_bwd_packets) if pd.notna(total_bwd_packets) else 0,
                "bytes_per_sec": float(flow_bytes_per_s) if pd.notna(flow_bytes_per_s) else 0
            }
        }

    def _determine_event_type(self, row: pd.Series, attack_type: str) -> str:
        """Determine specific event type from flow characteristics"""

        if attack_type == 'Normal':
            return 'NORMAL_TRAFFIC'

        # Port scanning detection
        dst_port = row.get('Destination Port', row.get(' Destination Port', 0))
        if attack_type == 'Reconnaissance' or (pd.notna(dst_port) and int(dst_port) < 1024):
            return 'PORT_SCAN'

        # Failed login attempts
        if attack_type == 'BruteForce':
            protocol = row.get('Protocol', row.get(' Protocol', ''))
            if 'SSH' in str(protocol).upper() or dst_port == 22:
                return 'FAILED_SSH_LOGIN'
            elif dst_port == 21:
                return 'FAILED_FTP_LOGIN'
            else:
                return 'FAILED_LOGIN'

        # DDoS/DoS
        if attack_type in ['DDoS', 'DoS']:
            return 'EXCESSIVE_REQUESTS'

        # Data exfiltration
        flow_bytes = row.get('Flow Bytes/s', 0)
        if pd.notna(flow_bytes) and float(flow_bytes) > 1000000:  # High bandwidth
            return 'LARGE_DATA_TRANSFER'

        # Web attacks
        if attack_type in ['WebAttack', 'SQLInjection']:
            return 'MALICIOUS_REQUEST'

        return 'SUSPICIOUS_ACTIVITY'

    def process_csv(self, csv_path: str, output_path: str, sample_size: int = None):
        """Process CICIDS2017 CSV and save normalized JSON"""

        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)

        if sample_size:
            print(f"Sampling {sample_size} events...")
            df = df.sample(min(sample_size, len(df)))

        print(f"Normalizing {len(df)} events...")
        normalized_events = []

        for idx, row in df.iterrows():
            try:
                event = self.normalize_cicids_event(row)
                normalized_events.append(event)
            except Exception as e:
                print(f"Warning: Failed to normalize row {idx}: {e}")
                continue

        # Save to JSON
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(normalized_events, f, indent=2)

        # Print statistics
        attack_counts = {}
        for event in normalized_events:
            attack_type = event['attack_type']
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

        print(f"\n✓ Normalized {len(normalized_events)} events")
        print(f"✓ Saved to {output_path}")
        print("\nAttack Distribution:")
        for attack, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {attack}: {count}")

        return normalized_events


def main():
    """Example usage"""
    normalizer = DataNormalizer()


    # Adjust paths according to your dataset location
    input_csv = r"C:\cyber_agentic_ai\data\raw\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    output_json = r"C:\cyber_agentic_ai\data\processed\normalized_events.json"

    # Process with sampling (remove sample_size for full dataset)
    normalizer.process_csv(
        csv_path=input_csv,
        output_path=output_json,
        sample_size=1000  # Start with 1000 events for testing
    )


if __name__ == "__main__":
    main()