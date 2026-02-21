#TODO: API Key Security Monitor

import os
import hashlib
import time
from datetime import datetime
from typing import Dict, List


class APIKeyMonitor:
    def __init__(self):
        self.key_usage_log = []
        self.suspicious_activities = []

    def monitor_api_keys(self) -> Dict:
        """Monitor API key usage patterns"""
        try:
            # Simulate checking API key usage (replace with actual monitoring)
            current_time = datetime.now()

            # Check environment for API key usage patterns
            key_activities = []

            for key_name in ['ROCKWELL_API_KEY', 'SIEMENS_API_KEY', 'AVEVA_API_KEY']:
                if os.getenv(key_name):
                    # Simulate usage pattern analysis
                    key_hash = hashlib.md5(os.getenv(key_name).encode()).hexdigest()[:8]
                    usage_count = len([log for log in self.key_usage_log
                                       if log.get('key') == key_name and
                                       (current_time - log.get('timestamp', current_time)).seconds < 3600])

                    activity = {
                        'key_name': key_name,
                        'key_hash': f"{key_hash}...",
                        'usage_count_last_hour': usage_count,
                        'last_used': current_time.isoformat(),
                        'suspicious': usage_count > 100  # Threshold
                    }

                    key_activities.append(activity)

                    if activity['suspicious']:
                        self.suspicious_activities.append(activity)

            result = {
                'timestamp': current_time.isoformat(),
                'keys_monitored': len(key_activities),
                'key_activities': key_activities,
                'suspicious_count': len([a for a in key_activities if a['suspicious']])
            }

            self.key_usage_log.append(result)
            return result

        except Exception as e:
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}

    def get_api_security_report(self) -> str:
        """Generate API key security report"""
        if not self.key_usage_log:
            return "No API key activity detected."

        recent_logs = self.key_usage_log[-5:]  # Last 5 checks

        report = "API Key Security Report:\n"
        report += f"Total keys monitored: {recent_logs[0].get('keys_monitored', 0)}\n"

        suspicious_count = sum(log.get('suspicious_count', 0) for log in recent_logs)
        report += f"Suspicious activities detected: {suspicious_count}\n"

        if suspicious_count > 0:
            report += "ALERT: Suspicious API key usage detected!\n"

        return report
