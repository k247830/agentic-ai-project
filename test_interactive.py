import sys
import json
from pathlib import Path

PROJECT_ROOT = Path("C:/cyber_agentic_ai")
sys.path.append(str(PROJECT_ROOT / "agents"))

from autonomous_orchestrator import AutonomousOrchestrator
from autonomous_executor import ExecutionMode

# Load events
events_file = PROJECT_ROOT / 'data/processed/normalized_events.json'

try:
    with open(events_file, 'r') as f:
        events = json.load(f)
    print(f"✅ Loaded {len(events)} events\n")
except FileNotFoundError:
    print(f"❌ File not found: {events_file}")
    print("Run parser.py first to generate normalized_events.json")
    exit(1)

print("""
╔══════════════════════════════════════════════════════════════╗
║   🤖 AUTONOMOUS SECURITY SYSTEM - INTERACTIVE MODE          ║
╚══════════════════════════════════════════════════════════════╝

Choose execution mode:
1. SIMULATION    (Safest - just logs, no real actions)
2. DRY_RUN       (Validation only - shows what would happen)
3. SUPERVISED    (Requires your approval for each action)
4. AUTONOMOUS    (⚠️  DANGEROUS - Real execution!)
5. Exit
""")

choice = input("Select mode (1-5): ").strip()

modes = {
    '1': ExecutionMode.SIMULATION,
    '2': ExecutionMode.DRY_RUN,
    '3': ExecutionMode.SUPERVISED,
    '4': ExecutionMode.AUTONOMOUS
}

if choice == '5':
    print("👋 Goodbye!")
    exit(0)

if choice not in modes:
    print("❌ Invalid choice")
    exit(1)

selected_mode = modes[choice]

# Warning for autonomous mode
if selected_mode == ExecutionMode.AUTONOMOUS:
    print("\n" + "=" * 70)
    print("⚠️  WARNING: AUTONOMOUS MODE SELECTED")
    print("=" * 70)
    print("This will execute REAL system commands!")
    print("Commands will be run on YOUR system!")
    print("=" * 70)
    confirm = input("\nType 'I UNDERSTAND THE RISKS' to continue: ")

    if confirm != 'I UNDERSTAND THE RISKS':
        print("❌ Aborted for safety")
        exit(0)

# Create orchestrator
print(f"\n🚀 Starting in {selected_mode.value} mode...")
orchestrator = AutonomousOrchestrator(selected_mode)

# Ask about auto-execution
auto_exec = input("\nAuto-execute actions? (yes/no): ").strip().lower() == 'yes'

# Run analysis and response
print("\n" + "=" * 70)
report = orchestrator.analyze_and_respond(events, auto_execute=auto_exec)

# Display results
print("\n" + "=" * 70)
print("📊 RESULTS SUMMARY")
print("=" * 70)

if report.get('autonomous_execution', {}).get('execution_results'):
    exec_results = report['autonomous_execution']['execution_results']

    print(f"\n✅ Actions Executed: {len(exec_results['actions_executed'])}")
    for action in exec_results['actions_executed'][:5]:
        print(f"   • {action['action']} on {action['target']}")

    print(f"\n🚫 Actions Blocked: {len(exec_results['actions_blocked'])}")
    for action in exec_results['actions_blocked'][:5]:
        print(f"   • {action['action']} on {action['target']}: {action['reason']}")

    print(f"\n❌ Actions Failed: {len(exec_results['actions_failed'])}")

    print(f"\n📊 Success Rate: {exec_results['success_rate']:.2%}")
else:
    print("\n⚠️  No execution performed (auto-execute was disabled)")

print("\n" + "=" * 70)
print("✅ COMPLETE!")
print("=" * 70)