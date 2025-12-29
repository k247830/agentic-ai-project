"""
Quick Start Script
Run this to set up and test the entire system
"""

import os
import json
from pathlib import Path
import subprocess
import sys


def create_directory_structure():
    """Create all necessary directories"""
    directories = [
        'data/raw',
        'data/processed',
        'data/reports',
        'data/evaluation',
        'agents',
        'api',
        'evaluation'
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

    print("✓ Directory structure created")


def create_requirements_file():
    """Create requirements.txt"""
    requirements = """fastapi==0.104.1
uvicorn[standard]==0.24.0
pandas==2.1.3
python-multipart==0.0.6
pydantic==2.5.0
numpy==1.24.3
"""

    with open('requirements.txt', 'w') as f:
        f.write(requirements)

    print("✓ requirements.txt created")


def create_sample_data():
    """Create sample normalized events for testing"""
    sample_events = [
        {
            "event_id": "evt_001",
            "timestamp": "2024-12-25T10:00:00",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "source_port": 54321,
            "destination_port": 22,
            "protocol": "TCP",
            "event_type": "FAILED_SSH_LOGIN",
            "attack_type": "BruteForce",
            "label": "SSH-Patator",
            "is_malicious": True,
            "flow_stats": {
                "duration": 1000,
                "fwd_packets": 5,
                "bwd_packets": 2,
                "bytes_per_sec": 500
            }
        },
        {
            "event_id": "evt_002",
            "timestamp": "2024-12-25T10:00:05",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "source_port": 54322,
            "destination_port": 22,
            "protocol": "TCP",
            "event_type": "FAILED_SSH_LOGIN",
            "attack_type": "BruteForce",
            "label": "SSH-Patator",
            "is_malicious": True,
            "flow_stats": {
                "duration": 1000,
                "fwd_packets": 5,
                "bwd_packets": 2,
                "bytes_per_sec": 500
            }
        },
        {
            "event_id": "evt_003",
            "timestamp": "2024-12-25T10:01:00",
            "source_ip": "203.0.113.5",
            "destination_ip": "10.0.0.10",
            "source_port": 80,
            "destination_port": 3306,
            "protocol": "TCP",
            "event_type": "MALICIOUS_REQUEST",
            "attack_type": "SQLInjection",
            "label": "Web Attack – Sql Injection",
            "is_malicious": True,
            "flow_stats": {
                "duration": 500,
                "fwd_packets": 3,
                "bwd_packets": 1,
                "bytes_per_sec": 1500
            }
        },
        {
            "event_id": "evt_004",
            "timestamp": "2024-12-25T10:02:00",
            "source_ip": "198.51.100.50",
            "destination_ip": "10.0.0.20",
            "source_port": 12345,
            "destination_port": 80,
            "protocol": "TCP",
            "event_type": "EXCESSIVE_REQUESTS",
            "attack_type": "DDoS",
            "label": "DDoS",
            "is_malicious": True,
            "flow_stats": {
                "duration": 100,
                "fwd_packets": 1000,
                "bwd_packets": 0,
                "bytes_per_sec": 50000
            }
        },
        {
            "event_id": "evt_005",
            "timestamp": "2024-12-25T10:03:00",
            "source_ip": "198.51.100.50",
            "destination_ip": "10.0.0.20",
            "source_port": 12346,
            "destination_port": 80,
            "protocol": "TCP",
            "event_type": "EXCESSIVE_REQUESTS",
            "attack_type": "DDoS",
            "label": "DDoS",
            "is_malicious": True,
            "flow_stats": {
                "duration": 100,
                "fwd_packets": 1000,
                "bwd_packets": 0,
                "bytes_per_sec": 50000
            }
        }
    ]

    # Add some benign events
    for i in range(10):
        sample_events.append({
            "event_id": f"evt_benign_{i}",
            "timestamp": f"2024-12-25T09:{str(i).zfill(2)}:00",
            "source_ip": f"10.0.1.{i + 1}",
            "destination_ip": "10.0.0.1",
            "source_port": 50000 + i,
            "destination_port": 443,
            "protocol": "TCP",
            "event_type": "NORMAL_TRAFFIC",
            "attack_type": "Normal",
            "label": "BENIGN",
            "is_malicious": False,
            "flow_stats": {
                "duration": 5000,
                "fwd_packets": 10,
                "bwd_packets": 10,
                "bytes_per_sec": 1000
            }
        })

    with open('data/processed/normalized_events.json', 'w') as f:
        json.dump(sample_events, f, indent=2)

    print(f"✓ Sample data created ({len(sample_events)} events)")


def install_dependencies():
    """Install required packages"""
    print("\n📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Dependencies installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        print("   Please run: pip install -r requirements.txt")


def run_demo_analysis():
    """Run a demo analysis"""
    print("\n🔍 Running demo analysis...")

    try:
        # Import after installation
        from agents.orchestrator import IncidentOrchestrator

        # Load sample events
        with open('data/processed/normalized_events.json', 'r') as f:
            events = json.load(f)

        # Run analysis
        orchestrator = IncidentOrchestrator()
        report = orchestrator.analyze_incident(events)

        # Save report
        orchestrator.save_report(report)

        print("\n✅ Analysis complete!")
        print("\n📊 Summary:")
        if report.get('attack_detected'):
            print(f"   Attacks Detected: {report['attack_intelligence']['total_attacks_detected']}")
            print(f"   Severity: {report['severity_assessment']['overall_severity']}")
            print(f"   Estimated Loss: ${report['business_impact']['financial_impact_usd']:,}")
        else:
            print("   No attacks detected")

        return True
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False


def print_next_steps():
    """Print next steps for the user"""
    print("\n" + "=" * 70)
    print("🎉 SETUP COMPLETE!")
    print("=" * 70)
    print("\n📝 Next Steps:")
    print("\n1. Run full analysis:")
    print("   python agents/orchestrator.py")
    print("\n2. Start web interface:")
    print("   python api/fastapi_demo.py")
    print("   Then open: http://localhost:8000")
    print("\n3. Run evaluation:")
    print("   python evaluation/evaluation.py")
    print("\n4. Use your own data:")
    print("   - Place CICIDS2017 CSV in data/raw/")
    print("   - Run: python agents/data_ingestion.py")
    print("\n📚 Documentation: See README.md for detailed usage")
    print("=" * 70)


def main():
    """Main setup function"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║   🛡️  SECURITY INCIDENT ANALYSIS SYSTEM                     ║
    ║                                                              ║
    ║   Quick Setup & Demo                                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    print("\n🚀 Starting setup...\n")

    # Step 1: Create directories
    create_directory_structure()

    # Step 2: Create requirements file
    create_requirements_file()

    # Step 3: Create sample data
    create_sample_data()

    # Step 4: Install dependencies
    response = input("\n📦 Install dependencies now? (y/n): ")
    if response.lower() == 'y':
        install_dependencies()
    else:
        print("⚠️  Skipped dependency installation")
        print("   Run manually: pip install -r requirements.txt")

    # Step 5: Run demo
    response = input("\n🔍 Run demo analysis? (y/n): ")
    if response.lower() == 'y':
        success = run_demo_analysis()
        if not success:
            print("\n⚠️  Demo analysis failed. Install dependencies first:")
            print("   pip install -r requirements.txt")

    # Print next steps
    print_next_steps()


if __name__ == "__main__":
    main()