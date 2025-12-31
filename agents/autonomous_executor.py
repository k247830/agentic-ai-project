"""
AUTONOMOUS ACTION EXECUTOR
⚠️ WARNING: This module can make REAL changes to systems
Use ONLY in controlled test environments with proper safeguards
"""

import subprocess
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum
import socket
from pathlib import Path

# ✅ CREATE LOGS DIRECTORY FIRST
LOGS_DIR = Path('C:/cyber_agentic_ai/data/logs')
LOGS_DIR.mkdir(parents=True, exist_ok=True)  # Creates directory if missing

# Configure logging (NOW this will work!)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / 'autonomous_actions.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Execution modes with increasing levels of autonomy"""
    SIMULATION = "simulation"
    DRY_RUN = "dry_run"
    SUPERVISED = "supervised"
    AUTONOMOUS = "autonomous"


class ActionStatus(Enum):
    """Status of executed actions"""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"


class SafetyValidator:
    """Validates actions before execution to prevent disasters"""

    def __init__(self):
        # Whitelist of IPs that should NEVER be blocked
        self.protected_ips = [
            "127.0.0.1",
            "localhost",
            "10.0.0.1",
            "8.8.8.8",
            "8.8.4.4"
        ]

        self.protected_accounts = [
            "admin",
            "administrator",
            "root",
            "emergency"
        ]

        self.max_blocks_per_action = 10
        self.confidence_threshold = 0.85

    def validate_action(self, action: Dict) -> tuple:
        """Validate if action is safe to execute"""
        action_type = action.get('action_type')
        target = action.get('target')
        confidence = action.get('confidence', 0)

        if confidence < self.confidence_threshold:
            return False, f"Confidence too low: {confidence:.2%}"

        if action_type == 'block_ip':
            if target in self.protected_ips:
                return False, f"Protected IP cannot be blocked: {target}"

            if not self._is_valid_ip(target):
                return False, f"Invalid IP address: {target}"

        if action_type == 'disable_account':
            if target.lower() in self.protected_accounts:
                return False, f"Protected account: {target}"

        return True, "Action validated successfully"

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


class ActionExecutor:
    """Executes security response actions autonomously"""

    def __init__(self, mode: ExecutionMode = ExecutionMode.SIMULATION, config: Dict = None):
        self.mode = mode
        self.config = config or {}
        self.validator = SafetyValidator()
        self.action_history = []

        logger.info(f"ActionExecutor initialized in {mode.value} mode")

        if mode == ExecutionMode.AUTONOMOUS:
            logger.warning("⚠️ AUTONOMOUS MODE ENABLED")

    def execute_response_plan(self, response_plan: Dict) -> Dict:
        """Execute full response plan with safety checks"""

        logger.info(f"Executing response plan: {response_plan.get('incident_id')}")

        execution_results = {
            'incident_id': response_plan.get('incident_id'),
            'execution_mode': self.mode.value,
            'started_at': datetime.now().isoformat(),
            'actions_executed': [],
            'actions_failed': [],
            'actions_blocked': []
        }

        immediate_actions = response_plan.get('immediate_actions', [])

        for action_item in immediate_actions:
            executable_action = self._parse_action(action_item)

            if executable_action:
                result = self.execute_action(executable_action)

                if result['status'] == ActionStatus.SUCCESS.value:
                    execution_results['actions_executed'].append(result)
                elif result['status'] == ActionStatus.BLOCKED.value:
                    execution_results['actions_blocked'].append(result)
                else:
                    execution_results['actions_failed'].append(result)

        execution_results['completed_at'] = datetime.now().isoformat()
        execution_results['success_rate'] = len(execution_results['actions_executed']) / max(len(immediate_actions), 1)

        self._save_execution_log(execution_results)

        return execution_results

    def execute_action(self, action: Dict) -> Dict:
        """Execute a single action with safety validation"""

        action_type = action.get('action_type')
        target = action.get('target')

        logger.info(f"Attempting to execute: {action_type} on {target}")

        # Safety validation
        is_safe, reason = self.validator.validate_action(action)

        if not is_safe:
            logger.warning(f"Action blocked: {reason}")
            return {
                'action': action_type,
                'target': target,
                'status': ActionStatus.BLOCKED.value,
                'reason': reason,
                'timestamp': datetime.now().isoformat()
            }

        # Mode-specific execution
        if self.mode == ExecutionMode.SIMULATION:
            return self._simulate_action(action)
        elif self.mode == ExecutionMode.DRY_RUN:
            return self._dry_run_action(action)
        elif self.mode == ExecutionMode.SUPERVISED:
            return self._supervised_action(action)
        elif self.mode == ExecutionMode.AUTONOMOUS:
            return self._execute_real_action(action)
        else:
            return {
                'action': action_type,
                'status': ActionStatus.FAILED.value,
                'reason': f"Unknown mode: {self.mode}"
            }

    def _parse_action(self, action_item: Dict) -> Optional[Dict]:
        """Convert text recommendation to executable action"""
        action_text = action_item.get('action', '').lower()
        attack_type = action_item.get('attack_type', '')

        # Parse "Block IP X.X.X.X"
        if 'block ip' in action_text or 'block source ip' in action_text:
            words = action_text.split()
            for word in words:
                if self._looks_like_ip(word):
                    return {
                        'action_type': 'block_ip',
                        'target': word,
                        'confidence': 0.9,
                        'reason': f"Response to {attack_type} attack"
                    }

        # Parse other actions...
        if 'disable' in action_text and 'account' in action_text:
            return {
                'action_type': 'disable_account',
                'target': 'suspected_user',
                'confidence': 0.85,
                'reason': f"Response to {attack_type} attack"
            }

        if 'rate limit' in action_text:
            return {
                'action_type': 'enable_rate_limiting',
                'target': 'ssh_service',
                'confidence': 0.95,
                'reason': f"Prevention for {attack_type}"
            }

        return None

    def _looks_like_ip(self, text: str) -> bool:
        """Quick check if text looks like IP address"""
        parts = text.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def _simulate_action(self, action: Dict) -> Dict:
        """Simulation mode - just logs"""
        logger.info(f"[SIMULATION] Would execute: {action}")

        return {
            'action': action['action_type'],
            'target': action['target'],
            'status': ActionStatus.SUCCESS.value,
            'mode': 'simulation',
            'message': 'Action simulated successfully',
            'timestamp': datetime.now().isoformat()
        }

    def _dry_run_action(self, action: Dict) -> Dict:
        """Dry run - validates but doesn't execute"""
        logger.info(f"[DRY RUN] Validating: {action}")

        return {
            'action': action['action_type'],
            'target': action['target'],
            'status': ActionStatus.SUCCESS.value,
            'mode': 'dry_run',
            'validations': ['Would validate command syntax', 'Would check connectivity']
        }

    def _supervised_action(self, action: Dict) -> Dict:
        """Supervised - requires approval"""
        print("\n" + "=" * 70)
        print("🚨 ACTION REQUIRES APPROVAL")
        print("=" * 70)
        print(f"Action: {action['action_type']}")
        print(f"Target: {action['target']}")
        print(f"Confidence: {action.get('confidence', 0):.2%}")
        print("=" * 70)

        approval = input("Approve? (yes/no): ").strip().lower()

        if approval == 'yes':
            logger.info("Action approved")
            return self._execute_real_action(action)
        else:
            logger.info("Action rejected")
            return {
                'action': action['action_type'],
                'target': action['target'],
                'status': ActionStatus.BLOCKED.value,
                'reason': 'Rejected by operator'
            }

    def _execute_real_action(self, action: Dict) -> Dict:
        """Actually execute (DANGEROUS!)"""
        action_type = action['action_type']
        target = action['target']

        logger.warning(f"[AUTONOMOUS] Executing: {action_type} on {target}")

        try:
            if action_type == 'block_ip':
                return self._block_ip(target)
            elif action_type == 'disable_account':
                return self._disable_account(target)
            else:
                return {
                    'action': action_type,
                    'status': ActionStatus.FAILED.value,
                    'reason': f"Unknown action: {action_type}"
                }
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            return {
                'action': action_type,
                'target': target,
                'status': ActionStatus.FAILED.value,
                'error': str(e)
            }

    def _block_ip(self, ip: str) -> Dict:
        """Block IP at firewall"""
        if self.mode != ExecutionMode.AUTONOMOUS:
            return {'status': ActionStatus.BLOCKED.value, 'reason': 'Not in autonomous mode'}

        try:
            # Windows firewall command
            command = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info(f"✅ Blocked IP: {ip}")
                return {
                    'action': 'block_ip',
                    'target': ip,
                    'status': ActionStatus.SUCCESS.value,
                    'method': 'netsh',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                raise Exception(f"Command failed: {result.stderr}")

        except Exception as e:
            return {
                'action': 'block_ip',
                'target': ip,
                'status': ActionStatus.FAILED.value,
                'error': str(e)
            }

    def _disable_account(self, username: str) -> Dict:
        """Disable user account"""
        try:
            # Windows command
            command = f'net user {username} /active:no'

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info(f"✅ Disabled account: {username}")
                return {
                    'action': 'disable_account',
                    'target': username,
                    'status': ActionStatus.SUCCESS.value,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                raise Exception(f"Command failed: {result.stderr}")

        except Exception as e:
            return {
                'action': 'disable_account',
                'target': username,
                'status': ActionStatus.FAILED.value,
                'error': str(e)
            }

    def _save_execution_log(self, results: Dict):
        """Save execution results"""
        log_file = f"C:/cyber_agentic_ai/data/logs/execution_{results['incident_id']}.json"
        with open(log_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Execution log saved: {log_file}")


def main():
    """Test"""
    print("Autonomous Executor loaded successfully!")


if __name__ == "__main__":
    main()