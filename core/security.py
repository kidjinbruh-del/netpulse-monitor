"""
Security Scanner - обнаружение угроз
"""

import os
import sys
import subprocess
import re
import fnmatch
import logging

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def _is_whitelisted_name(name):
    """Проверка имени процесса: точные совпадения + fnmask-wildcards"""
    name_lower = name.lower()
    for pattern in SecurityScanner.WHITELIST_PROCESSES:
        pattern_lower = pattern.lower()
        if '*' in pattern_lower:
            if fnmatch.fnmatch(name_lower, pattern_lower):
                return True
        elif name_lower == pattern_lower:
            return True
    return False

class SecurityScanner:
    WHITELIST_PROCESSES = {
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'opera.exe',
        'svchost.exe', 'explorer.exe', 'winlogon.exe', 'services.exe',
        'python.exe', 'python3.exe', 'pycharm.exe', 'code.exe',
        'Code.exe', 'CodeSetup*.exe', 'CodeSetup*.tmp',
        'vscode*.exe', 'vscode*.tmp',
        'docker.exe', 'docker-desktop.exe',
        'msbuild.exe', 'devenv.exe'
    }
    
    WHITELIST_PATHS = {
        'windows', 'program files', 'microsoft', 'visual studio', 
        'jetbrains', 'intellij', 'android studio',
        'vscode-stable-user-x64', 'is-'
    }
    
    LEGITIMATE_IPS = {'127.0.0.1', '0.0.0.0', '::1'}
    LEGITIMATE_DOMAINS = {'localhost', 'localhost.localdomain'}
    
    @staticmethod
    def detect_suspicious_connections(suspicious_ports=None):
        if suspicious_ports is None:
            suspicious_ports = [4444, 1337, 31337, 6667, 4443, 8080, 8888, 3389, 5900, 22, 23]
        
        suspicious = []
        
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                result = subprocess.run(
                    ["netstat", "-tunp"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            
            for line in result.stdout.split('\n'):
                if ':' in line and '.' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            if sys.platform == "win32":
                                remote = parts[2]
                                pid = parts[-1]
                            else:
                                if len(parts) >= 7:
                                    remote = parts[4]
                                    pid = parts[6].split('/')[0]
                                else:
                                    continue
                            
                            remote_port = remote.rsplit(':', 1)[-1] if ':' in remote else ''
                            if remote_port and remote_port.isdigit():
                                port = int(remote_port)
                                if port in suspicious_ports:
                                    proc_name = f"PID:{pid}"
                                    if PSUTIL_AVAILABLE:
                                        try:
                                            proc_name = psutil.Process(int(pid)).name()
                                        except:
                                            pass
                                    
                                    suspicious.append({
                                        "process": proc_name,
                                        "pid": pid,
                                        "remote": remote,
                                        "reason": f"Подозрительный порт {port}",
                                        "severity": "HIGH"
                                    })
                        except (ValueError, IndexError):
                            continue
        except subprocess.TimeoutExpired:
            logger.warning("Таймаут при сканировании соединений")
        except Exception as e:
            logger.error(f"Ошибка сканирования соединений: {e}")
        
        return suspicious
    
    @staticmethod
    def detect_hidden_processes():
        if not PSUTIL_AVAILABLE:
            return []
        
        hidden = []
        if sys.platform == "win32":
            suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads', 'cache']
        else:
            suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '.cache']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or 'unknown'
                    exe_path = proc.info['exe'] or ''
                    
                    is_whitelisted = (
                        _is_whitelisted_name(name) or
                        any(wp in exe_path.lower() for wp in SecurityScanner.WHITELIST_PATHS)
                    )
                    
                    if is_whitelisted:
                        continue
                    
                    if any(path in exe_path.lower() for path in suspicious_paths):
                        connections = 0
                        try:
                            if hasattr(proc, 'net_connections'):
                                net_conns = proc.net_connections()
                            elif hasattr(proc, 'connections'):
                                net_conns = proc.connections()
                            else:
                                net_conns = []
                            connections = len(net_conns)
                        except:
                            pass
                        
                        hidden.append({
                            "process": name,
                            "pid": pid,
                            "reason": "Запущен из подозрительной директории",
                            "connections": connections,
                            "path": exe_path,
                            "severity": "MEDIUM" if connections == 0 else "HIGH"
                        })
                        
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                except Exception as e:
                    logger.debug(f"Ошибка проверки процесса: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования процессов: {e}")
        
        return hidden
    
    @staticmethod
    def check_hosts_file():
        suspicious = []
        
        if sys.platform == "win32":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        else:
            hosts_path = "/etc/hosts"
        
        if not os.path.exists(hosts_path):
            logger.debug(f"Файл hosts не найден: {hosts_path}")
            return suspicious
        
        if not os.access(hosts_path, os.R_OK):
            logger.warning(f"Нет прав на чтение файла hosts: {hosts_path}")
            return suspicious
        
        known_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'vk.com', 'yandex.ru',
            'microsoft.com', 'apple.com', 'steam.com', 'discord.com', 'telegram.org',
            'github.com', 'twitter.com', 'instagram.com', 'whatsapp.com'
        ]
        
        try:
            with open(hosts_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    ip = parts[0]
                    if ip in SecurityScanner.LEGITIMATE_IPS:
                        continue
                    
                    domains_text = ' '.join(parts[1:]).lower()
                    found_domains = set()
                    
                    for domain in known_domains:
                        if re.search(r'\b' + re.escape(domain) + r'\b', domains_text):
                            found_domains.add(domain)
                    
                    for domain in found_domains:
                        if domain in SecurityScanner.LEGITIMATE_DOMAINS:
                            continue
                        
                        suspicious.append({
                            "domain": domains_text,
                            "redirects_to": ip,
                            "reason": f"Перенаправление {domain}",
                            "severity": "CRITICAL",
                            "line": line_num
                        })
        except Exception as e:
            logger.error(f"Ошибка проверки hosts: {e}")
        
        return suspicious
    
    @staticmethod
    def check_autorun():
        suspicious = []
        
        try:
            if sys.platform == "win32":
                reg_paths = [
                    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
                ]
                
                for reg_path in reg_paths:
                    result = subprocess.run(
                        ["reg", "query", reg_path],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    for line in result.stdout.split('\n'):
                        if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                            suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads']
                            if any(path in line.lower() for path in suspicious_paths):
                                suspicious.append({
                                    "entry": line.strip()[:100],
                                    "reason": "Подозрительная автозагрузка",
                                    "severity": "MEDIUM"
                                })
            else:
                try:
                    result = subprocess.run(
                        ["crontab", "-l"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if any(path in line for path in ['/tmp/', '/var/tmp/', '.cache']):
                                suspicious.append({
                                    "entry": line[:100],
                                    "reason": "Подозрительная запись в crontab",
                                    "severity": "HIGH"
                                })
                except:
                    pass
                
                autostart_dirs = [
                    os.path.expanduser("~/.config/autostart"),
                    "/etc/xdg/autostart"
                ]
                for dir_path in autostart_dirs:
                    if os.path.exists(dir_path):
                        for file in os.listdir(dir_path):
                            if file.endswith('.desktop'):
                                try:
                                    with open(os.path.join(dir_path, file), 'r', encoding='utf-8') as f:
                                        content = f.read()
                                        if 'Exec=' in content:
                                            suspicious.append({
                                                "entry": f"{file} в {dir_path}",
                                                "reason": "Автозагрузка",
                                                "severity": "MEDIUM"
                                            })
                                except:
                                    pass
        except Exception as e:
            logger.error(f"Ошибка проверки автозагрузки: {e}")
        
        return suspicious
    
    @staticmethod
    def run_full_scan(suspicious_ports=None):
        logger.info("Запуск сканирования безопасности...")
        
        results = {
            "Подозрительные соединения": SecurityScanner.detect_suspicious_connections(suspicious_ports),
            "Скрытые процессы": SecurityScanner.detect_hidden_processes(),
            "HOSTS файл": SecurityScanner.check_hosts_file(),
            "Автозагрузка": SecurityScanner.check_autorun()
        }
        
        total_threats = sum(len(v) for v in results.values())
        logger.info(f"Сканирование завершено. Найдено угроз: {total_threats}")
        return results