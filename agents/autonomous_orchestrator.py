"""
AUTONOMOUS ORCHESTRATOR
Integrates autonomous execution with existing system
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# ========================================
# FIX IMPORTS - For your folder structure
# ========================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # C:\cyber_agentic_ai
AGENTS_DIR = PROJECT_ROOT / "agents"
ORCHESTRATOR_DIR = PROJECT_ROOT / "orchestrator"  # ← Add this!

# Add both directories to Python path
sys.path.insert(0, str(AGENTS_DIR))
sys.path.insert(0, str(ORCHESTRATOR_DIR))  # ← Add this!

print(f"📁 Project Root: {PROJECT_ROOT}")
print(f"📁 Agents Dir: {AGENTS_DIR}")
print(f"📁 Orchestrator Dir: {ORCHESTRATOR_DIR}")

# Now import from the correct locations
try:
    from orchestrator import IncidentOrchestrator
    print("✅ IncidentOrchestrator imported")
except ImportError as e:
    print(f"❌ Failed to import IncidentOrchestrator: {e}")
    print(f"   Looking in: {ORCHESTRATOR_DIR / 'orchestrator.py'}")
    print(f"   File exists: {(ORCHESTRATOR_DIR / 'orchestrator.py').exists()}")
    raise

try:
    from autonomous_executor import ActionExecutor, ExecutionMode
    print("✅ ActionExecutor imported")
except ImportError as e:
    print(f"❌ Failed to import ActionExecutor: {e}")
    raise


class AutonomousOrchestrator(IncidentOrchestrator):
    """Extended orchestrator with autonomous execution"""

    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SIMULATION):
        super().__init__()
        self.execution_mode = execution_mode
        self.executor = ActionExecutor(mode=execution_mode)

        print(f"\n⚙️  Autonomous Orchestrator - {execution_mode.value} mode")

    def analyze_and_respond(self, events: List[Dict], auto_execute: bool = False) -> Dict:
        """Complete workflow: Analyze AND execute"""

        print("\n" + "="*70)
        print("🤖 AUTONOMOUS SECURITY ORCHESTRATOR")
        print("="*70)
        print(f"Mode: {self.execution_mode.value}")
        print(f"Auto-Execute: {auto_execute}")
        print("="*70)

        # Run normal analysis (Phases 1-4)
        print("\n[PHASES 1-4] Running analysis...")
        analysis_report = self.analyze_incident(events, save_intermediates=True)

        if not analysis_report.get('attack_intelligence', {}).get('total_attacks_detected'):
            print("\n✅ No attacks - no actions needed")
            return analysis_report

        print(f"\n✅ Analysis complete - {analysis_report['attack_intelligence']['total_attacks_detected']} attacks")

        # Phase 5: Execution (NEW!)
        execution_results = None

        if auto_execute:
            print("\n[PHASE 5] Executing autonomous response...")

            response_plan = {
                'incident_id': analysis_report.get('incident_id'),
                'immediate_actions': analysis_report.get('incident_response', {}).get('immediate_actions', [])
            }

            execution_results = self.executor.execute_response_plan(response_plan)

            print(f"\n✅ Execution complete:")
            print(f"   Executed: {len(execution_results['actions_executed'])}")
            print(f"   Blocked: {len(execution_results['actions_blocked'])}")
            print(f"   Success: {execution_results['success_rate']:.2%}")
        else:
            print("\n⚠️  Auto-execute disabled")

        # Combine results
        combined_report = {
            **analysis_report,
            'autonomous_execution': {
                'enabled': auto_execute,
                'execution_mode': self.execution_mode.value,
                'execution_results': execution_results
            }
        }

        # Save
        report_path = self._save_autonomous_report(combined_report)
        print(f"\n📄 Report saved: {report_path}")

        return combined_report

    def _save_autonomous_report(self, report: Dict) -> str:
        """Save autonomous report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"autonomous_report_{timestamp}.json"
        filepath = PROJECT_ROOT / 'data' / 'reports' / filename

        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)

        return str(filepath)


def main():
    """Demo"""
    print("\n" + "="*70)
    print("Testing Autonomous System...")
    print("="*70)

    # Load events
    events_file = PROJECT_ROOT / 'data/processed/normalized_events.json'

    try:
        with open(events_file, 'r') as f:
            events = json.load(f)
    except FileNotFoundError:
        print(f"\n❌ File not found: {events_file}")
        print("\n💡 Run this first:")
        print(f"   cd {AGENTS_DIR}")
        print("   python parser.py")
        return

    print(f"✅ Loaded {len(events)} events")

    # Test SIMULATION mode
    print("\n" + "="*70)
    print("Testing in SIMULATION mode (safest)")
    print("="*70)

    orchestrator = AutonomousOrchestrator(ExecutionMode.SIMULATION)
    report = orchestrator.analyze_and_respond(events, auto_execute=True)

    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)

    if report.get('autonomous_execution', {}).get('execution_results'):
        exec_results = report['autonomous_execution']['execution_results']
        print(f"✅ Actions simulated: {len(exec_results['actions_executed'])}")
        print(f"🚫 Actions blocked: {len(exec_results['actions_blocked'])}")
        print(f"📊 Success rate: {exec_results['success_rate']:.2%}")


if __name__ == "__main__":
    main()

