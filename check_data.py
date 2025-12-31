import json
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path("C:/cyber_agentic_ai")
events_file = PROJECT_ROOT / "data/processed/normalized_events.json"

print("🔍 Checking normalized events...\n")

try:
    with open(events_file, 'r') as f:
        events = json.load(f)

    print(f"✅ Loaded {len(events)} events\n")

    # Check malicious vs benign
    malicious = [e for e in events if e.get('is_malicious', False)]
    benign = [e for e in events if not e.get('is_malicious', False)]

    print("=" * 70)
    print("MALICIOUS vs BENIGN")
    print("=" * 70)
    print(f"Malicious events: {len(malicious)}")
    print(f"Benign events: {len(benign)}")

    # Check attack types
    print("\n" + "=" * 70)
    print("ATTACK TYPE DISTRIBUTION")
    print("=" * 70)
    attack_types = Counter(e.get('attack_type', 'Unknown') for e in events)
    for attack, count in attack_types.most_common():
        print(f"{attack}: {count}")

    # Check labels
    print("\n" + "=" * 70)
    print("ORIGINAL LABELS")
    print("=" * 70)
    labels = Counter(e.get('label', 'Unknown') for e in events)
    for label, count in labels.most_common(10):
        print(f"{label}: {count}")

    # Sample events
    print("\n" + "=" * 70)
    print("SAMPLE EVENTS (First 3)")
    print("=" * 70)
    for i, event in enumerate(events[:3], 1):
        print(f"\nEvent {i}:")
        print(f"  Label: {event.get('label')}")
        print(f"  Attack Type: {event.get('attack_type')}")
        print(f"  Is Malicious: {event.get('is_malicious')}")
        print(f"  Event Type: {event.get('event_type')}")
        print(f"  Source IP: {event.get('source_ip')}")

    # Check for malicious events details
    if malicious:
        print("\n" + "=" * 70)
        print("MALICIOUS EVENTS DETAILS")
        print("=" * 70)
        malicious_types = Counter(e.get('attack_type') for e in malicious)
        for attack, count in malicious_types.most_common():
            print(f"{attack}: {count}")
    else:
        print("\n" + "=" * 70)
        print("⚠️  WARNING: NO MALICIOUS EVENTS FOUND!")
        print("=" * 70)
        print("\nPossible issues:")
        print("1. Dataset only contains BENIGN traffic")
        print("2. Label column not mapped correctly in parser.py")
        print("3. Sample size too small")

except FileNotFoundError:
    print(f"❌ File not found: {events_file}")
    print("\nRun parser.py first to generate normalized_events.json")
except json.JSONDecodeError as e:
    print(f"❌ Invalid JSON: {e}")