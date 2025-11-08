#!/usr/bin/env python3
"""
Nginx IP Monitor - automated monitoring and banning of suspicious IPs
Checks nginx logs, analyzes IPs and bans spammers/bots
"""

import os
import sys
import re
import json
import ipaddress
import requests
import time
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# Configuration - using environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "")

LOG_FILE = os.getenv("LOG_FILE", "/var/log/nginx/access.log")
LOG_OUTPUT = os.getenv("LOG_OUTPUT", "/var/log/nginx-ip-monitor.log")
BANNED_IPS_FILE = os.getenv("BANNED_IPS_FILE", "./banned_ips.txt")
BANS_DATABASE_FILE = os.getenv("BANS_DATABASE_FILE", "./bans_database.json")
BAN_EXPIRY_DAYS = int(os.getenv("BAN_EXPIRY_DAYS", "60"))  # 2 months

# Cloudflare IP ranges
CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

# Legitimate bots (User-Agent)
LEGITIMATE_BOTS = [
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider", "yandex",
    "facebookexternalhit", "twitterbot", "rogerbot", "linkedinbot", "embedly",
    "quora", "pinterest", "bitlybot", "tumblr", "vkShare", "W3C_Validator",
    "whatsapp", "flipboard", "developers.google.com", "msnbot", "ia_archiver",
    "archive.org_bot", "applebot"
]

# Sensitive paths (access to these paths = immediate ban)
SENSITIVE_PATTERNS = [
    # Configuration files
    r"\.env", r"\.env\.", r"\.git", r"\.git/", r"\.git/config", r"\.git/HEAD",
    r"\.sql", r"\.bak", r"\.backup", r"\.old", r"\.dump", r"\.sqlite", r"\.db",
    r"\.htaccess", r"\.htpasswd", r"\.gitlab-ci\.yml", r"\.gitignore",
    r"\.git/config", r"\.git/HEAD", r"\.git/index", r"\.git/objects",
    r"\.svn", r"\.hg", r"\.bzr", r"\.cvs",
    # WordPress
    r"wp-admin", r"wp-login\.php", r"wp-content", r"wp-includes",
    r"xmlrpc\.php", r"wp-config\.php", r"wp-config\.bak",
    # PHP admin panels
    r"phpmyadmin", r"pma", r"myadmin", r"adminer", r"adminer\.php",
    r"admin\.php", r"administrator", r"admin/", r"admin/index\.php",
    # Suspicious PHP files
    r"shell\.php", r"cmd\.php", r"eval\.php", r"c99\.php", r"r57\.php",
    r"wso\.php", r"b374k\.php", r"cpanel\.php", r"config\.php",
    r"phpinfo\.php", r"info\.php", r"test\.php", r"test\.php",
    # Other suspicious paths
    r"\.well-known/admin", r"\.well-known/log", r"\.well-known/php",
    r"\.well-known/security\.txt", r"\.well-known/acme-challenge",
    r"backup", r"backups", r"backup\.tar", r"backup\.zip",
    r"config", r"configuration", r"settings", r"setup",
    r"install", r"installer", r"upgrade", r"update",
    r"debug", r"test", r"testing", r"dev", r"development",
    r"\.log", r"logs", r"error_log", r"access_log",
    r"\.ssh", r"\.docker", r"\.vagrant", r"\.idea",
    r"\.vscode", r"\.DS_Store", r"\.gitkeep", r"\.gitattributes"
]

# Datacenters (usage types)
DATACENTER_TYPES = [
    "Data Center", "Hosting", "Transit", "Hosting Provider", "CDN", "Cloud Provider"
]

# IP whitelist (servers, legitimate IPs) - configure for your needs
WHITELIST_IPS = [
    "127.0.0.1",
    "::1"
]

# Ban thresholds
MIN_REQUESTS_FOR_ANALYSIS = int(os.getenv("MIN_REQUESTS_FOR_ANALYSIS", "5"))
MIN_404_ERRORS = int(os.getenv("MIN_404_ERRORS", "2"))
MIN_UNIQUE_PATHS = int(os.getenv("MIN_UNIQUE_PATHS", "5"))
ABUSEIPDB_CONFIDENCE_THRESHOLD = int(os.getenv("ABUSEIPDB_CONFIDENCE_THRESHOLD", "30"))


def log_message(message: str, level: str = "INFO"):
    """Log messages"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - [{level}] {message}\n"
    
    try:
        with open(LOG_OUTPUT, "a") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing to log: {e}")
    
    if level == "ERROR":
        print(f"ERROR: {message}", file=sys.stderr)
    elif level == "WARNING":
        print(f"WARNING: {message}")


def is_cloudflare_ip(ip: str) -> bool:
    """Check if IP belongs to Cloudflare"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in CLOUDFLARE_RANGES:
            if ip_obj in ipaddress.ip_network(range_str, strict=False):
                return True
    except Exception:
        pass
    return False


def is_legitimate_bot(user_agent: str) -> bool:
    """Check if this is a legitimate bot"""
    if not user_agent:
        return False
    user_agent_lower = user_agent.lower()
    return any(bot.lower() in user_agent_lower for bot in LEGITIMATE_BOTS)


def check_abuseipdb(ip: str) -> Tuple[Optional[int], Optional[str], bool]:
    """Check IP in AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        log_message("ABUSEIPDB_API_KEY not set, skipping AbuseIPDB check", "WARNING")
        return None, None, False
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code != 200:
            return None, None, False
        
        data = response.json()
        if "data" not in data:
            return None, None, False
        
        abuse_confidence = data["data"].get("abuseConfidenceScore", 0)
        usage_type = data["data"].get("usageType", "")
        is_whitelisted = data["data"].get("isWhitelisted", False)
        
        return abuse_confidence, usage_type, is_whitelisted
    except Exception as e:
        log_message(f"Error checking AbuseIPDB for {ip}: {e}", "ERROR")
        return None, None, False


def report_to_abuseipdb(ip: str, categories: str, comment: str) -> bool:
    """Report IP to AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        log_message("ABUSEIPDB_API_KEY not set, skipping AbuseIPDB report", "WARNING")
        return False
    
    try:
        url = "https://api.abuseipdb.com/api/v2/report"
        data = {
            "ip": ip,
            "categories": categories,
            "comment": comment
        }
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.post(url, data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get("errors"):
                log_message(f"AbuseIPDB report error for {ip}: {result.get('errors')}", "ERROR")
                return False
            log_message(f"Successfully reported {ip} to AbuseIPDB: {comment}")
            return True
        else:
            log_message(f"Failed to report {ip} to AbuseIPDB: HTTP {response.status_code}", "ERROR")
            return False
    except Exception as e:
        log_message(f"Error reporting to AbuseIPDB for {ip}: {e}", "ERROR")
        return False


def block_in_cloudflare(ip: str, reason: str) -> bool:
    """Block IP in Cloudflare at account level (all zones of all accounts)"""
    if not CLOUDFLARE_API_TOKEN:
        log_message("CLOUDFLARE_API_TOKEN not set, skipping Cloudflare blocking", "WARNING")
        return False
    
    try:
        headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        notes = f"[nginx-ip-monitor] {timestamp} - {reason}"
        
        # First try to get all accounts directly
        accounts_url = "https://api.cloudflare.com/client/v4/accounts"
        accounts_response = requests.get(accounts_url, headers=headers, timeout=10)
        
        accounts_to_block = []
        
        if accounts_response.status_code == 200:
            accounts_data = accounts_response.json()
            if accounts_data.get("success"):
                accounts = accounts_data.get("result", [])
                if accounts:
                    # If we got accounts directly - use them
                    for account in accounts:
                        accounts_to_block.append({
                            "id": account["id"],
                            "name": account.get("name", account["id"])
                        })
        
        # If we couldn't get accounts directly - get them through zones
        if not accounts_to_block:
            log_message("Cannot get accounts directly, getting account IDs from zones", "INFO")
            zones_url = "https://api.cloudflare.com/client/v4/zones"
            zones_response = requests.get(zones_url, headers=headers, timeout=10)
            
            if zones_response.status_code == 200:
                zones_data = zones_response.json()
                if zones_data.get("success"):
                    zones = zones_data.get("result", [])
                    # Collect unique account_id from all zones
                    account_ids = {}
                    for zone in zones:
                        account_info = zone.get("account", {})
                        account_id = account_info.get("id")
                        account_name = account_info.get("name")
                        if account_id and account_id not in account_ids:
                            account_ids[account_id] = account_name or account_id or "Unknown Account"
                    
                    # Add all unique accounts to the list
                    for account_id, account_name in account_ids.items():
                        accounts_to_block.append({
                            "id": account_id,
                            "name": account_name
                        })
                    
                    log_message(f"Found {len(accounts_to_block)} unique account(s) from {len(zones)} zone(s)", "INFO")
        
        if not accounts_to_block:
            log_message("No Cloudflare accounts found, trying zone-level blocking", "WARNING")
            return block_in_cloudflare_zones(ip, reason, headers, notes)
        
        # Block IP at each account level (applies to all zones in the account)
        success_count = 0
        for account in accounts_to_block:
            account_id = account["id"]
            account_name = account["name"]
            
            # Check if rule already exists at account level
            check_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/firewall/access_rules/rules"
            check_params = {
                "configuration.target": "ip",
                "configuration.value": ip,
                "page": 1,
                "per_page": 1
            }
            
            check_response = requests.get(check_url, params=check_params, headers=headers, timeout=10)
            existing_rule_id = None
            
            if check_response.status_code == 200:
                check_data = check_response.json()
                if check_data.get("success") and check_data.get("result"):
                    rules = check_data.get("result", [])
                    if rules:
                        existing_rule_id = rules[0].get("id")
                        log_message(f"Found existing account-level rule for {ip} in account {account_name}")
            elif check_response.status_code == 403:
                log_message(f"No permission to check account-level rules for account {account_name}, skipping this account", "WARNING")
                # Skip this account, but continue with others
                continue
            
            if existing_rule_id:
                # Update existing rule at account level
                update_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/firewall/access_rules/rules/{existing_rule_id}"
                update_data = {
                    "mode": "block",
                    "notes": notes
                }
                update_response = requests.put(update_url, json=update_data, headers=headers, timeout=10)
                # Save ban record (if not already saved)
                save_ban_record(ip, account_id, None, existing_rule_id, "account")
            else:
                # Create new rule at account level (applies to all zones)
                create_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/firewall/access_rules/rules"
                create_data = {
                    "mode": "block",
                    "configuration": {
                        "target": "ip",
                        "value": ip
                    },
                    "notes": notes
                }
                update_response = requests.post(create_url, json=create_data, headers=headers, timeout=10)
            
            if update_response.status_code in [200, 201]:
                update_data = update_response.json()
                if update_data.get("success"):
                    success_count += 1
                    rule_scope = update_data.get("result", {}).get("scope", {})
                    scope_type = rule_scope.get("type", "unknown")
                    rule_id = update_data.get("result", {}).get("id")
                    log_message(f"Blocked {ip} in Cloudflare account {account_name} (scope: {scope_type}, applies to ALL zones in account)")
                    # Save ban record
                    if rule_id:
                        save_ban_record(ip, account_id, None, rule_id, "account")
                else:
                    log_message(f"Failed to block {ip} in account {account_name}: {update_data}", "ERROR")
            elif update_response.status_code == 403:
                log_message(f"No permission to create account-level rules for account {account_name}, skipping this account", "WARNING")
                # Skip this account, but continue with others
                continue
            elif update_response.status_code == 400:
                # Possibly a problem with IP format or request
                error_data = update_response.json()
                error_msg = error_data.get("errors", [{}])[0].get("message", "Unknown error")
                log_message(f"Failed to block {ip} in account {account_name}: {error_msg}", "ERROR")
                continue
            else:
                log_message(f"Failed to block {ip} in account {account_name}: HTTP {update_response.status_code}, Response: {update_response.text}", "ERROR")
            
            time.sleep(0.1)  # Delay for rate limiting
        
        if success_count > 0:
            log_message(f"Successfully blocked {ip} in {success_count} Cloudflare account(s) out of {len(accounts_to_block)} (applies to ALL zones in each account)")
            return True
        else:
            log_message(f"Failed to block {ip} in any Cloudflare account ({len(accounts_to_block)} accounts tried) - API token may not have account-level permissions", "WARNING")
            log_message(f"Falling back to zone-level blocking for all zones", "INFO")
            return block_in_cloudflare_zones(ip, reason, headers, notes)
    except Exception as e:
        log_message(f"Error blocking in Cloudflare for {ip}: {e}", "ERROR")
        import traceback
        log_message(f"Traceback: {traceback.format_exc()}", "ERROR")
        # Fallback: try to block at zone level
        try:
            return block_in_cloudflare_zones(ip, reason, {
                "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
                "Content-Type": "application/json"
            }, f"[nginx-ip-monitor] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {reason}")
        except:
            return False


def block_in_cloudflare_zones(ip: str, reason: str, headers: dict, notes: str) -> bool:
    """Fallback: block IP in Cloudflare at zone level (if account-level doesn't work)"""
    try:
        # Get all zones
        url = "https://api.cloudflare.com/client/v4/zones"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return False
        
        zones_data = response.json()
        if not zones_data.get("success"):
            return False
        
        zones = zones_data.get("result", [])
        if not zones:
            return False
        
        success_count = 0
        for zone in zones:
            zone_id = zone["id"]
            zone_name = zone["name"]
            
            # Check if rule already exists
            check_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
            check_params = {
                "configuration.target": "ip",
                "configuration.value": ip,
                "page": 1,
                "per_page": 1
            }
            
            check_response = requests.get(check_url, params=check_params, headers=headers, timeout=10)
            existing_rule_id = None
            
            if check_response.status_code == 200:
                check_data = check_response.json()
                if check_data.get("success") and check_data.get("result"):
                    existing_rule_id = check_data["result"][0].get("id")
            
            if existing_rule_id:
                # Update existing rule
                update_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules/{existing_rule_id}"
                update_data = {"mode": "block", "notes": notes}
                update_response = requests.put(update_url, json=update_data, headers=headers, timeout=10)
                # Save ban record (if not already saved)
                save_ban_record(ip, None, zone_id, existing_rule_id, "zone")
            else:
                # Create new rule
                create_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
                create_data = {
                    "mode": "block",
                    "configuration": {"target": "ip", "value": ip},
                    "notes": notes
                }
                update_response = requests.post(create_url, json=create_data, headers=headers, timeout=10)
            
            if update_response.status_code in [200, 201]:
                update_data = update_response.json()
                if update_data.get("success"):
                    success_count += 1
            
            time.sleep(0.05)  # Затримка для rate limiting
        
        if success_count > 0:
            log_message(f"Blocked {ip} in {success_count} Cloudflare zone(s) out of {len(zones)} total zones")
            if success_count < len(zones):
                log_message(f"Warning: {len(zones) - success_count} zone(s) were not blocked", "WARNING")
            return True
        return False
    except Exception:
        return False


def is_already_banned(ip: str) -> bool:
    """Check if IP is already banned"""
    try:
        if os.path.exists(BANNED_IPS_FILE):
            with open(BANNED_IPS_FILE, "r") as f:
                banned_ips = {line.strip() for line in f if line.strip()}
                return ip in banned_ips
    except Exception:
        pass
    return False


def mark_as_banned(ip: str):
    """Mark IP as banned"""
    try:
        with open(BANNED_IPS_FILE, "a") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        log_message(f"Error marking {ip} as banned: {e}", "ERROR")


def save_ban_record(ip: str, account_id: Optional[str], zone_id: Optional[str], rule_id: str, rule_type: str):
    """Save ban information for later removal"""
    try:
        # Load existing records
        bans_db = {}
        if os.path.exists(BANS_DATABASE_FILE):
            try:
                with open(BANS_DATABASE_FILE, "r") as f:
                    bans_db = json.load(f)
            except Exception:
                bans_db = {}
        
        # Add new record
        ban_key = f"{ip}_{rule_type}_{rule_id}"
        bans_db[ban_key] = {
            "ip": ip,
            "account_id": account_id,
            "zone_id": zone_id,
            "rule_id": rule_id,
            "rule_type": rule_type,  # "account" or "zone"
            "created_at": datetime.now().isoformat(),
            "created_timestamp": datetime.now().timestamp()
        }
        
        # Зберегти
        with open(BANS_DATABASE_FILE, "w") as f:
            json.dump(bans_db, f, indent=2)
        
        log_message(f"Saved ban record for {ip} (rule_id: {rule_id}, type: {rule_type})")
    except Exception as e:
        log_message(f"Error saving ban record for {ip}: {e}", "ERROR")


def delete_old_bans():
    """Delete old bans (older than BAN_EXPIRY_DAYS days) created by our service"""
    if not CLOUDFLARE_API_TOKEN:
        log_message("CLOUDFLARE_API_TOKEN not set, skipping old bans deletion", "WARNING")
        return
    
    try:
        if not os.path.exists(BANS_DATABASE_FILE):
            return
        
        # Load records
        with open(BANS_DATABASE_FILE, "r") as f:
            bans_db = json.load(f)
        
        if not bans_db:
            return
        
        headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        expiry_date = datetime.now() - timedelta(days=BAN_EXPIRY_DAYS)
        deleted_count = 0
        bans_to_remove = []
        
        log_message(f"Checking for old bans created by nginx-ip-monitor (older than {BAN_EXPIRY_DAYS} days)...")
        
        for ban_key, ban_info in bans_db.items():
            try:
                created_at_str = ban_info.get("created_at")
                if not created_at_str:
                    continue
                
                created_at = datetime.fromisoformat(created_at_str)
                
                # Check if ban is older than BAN_EXPIRY_DAYS days
                if created_at < expiry_date:
                    ip = ban_info.get("ip")
                    rule_id = ban_info.get("rule_id")
                    rule_type = ban_info.get("rule_type")
                    account_id = ban_info.get("account_id")
                    zone_id = ban_info.get("zone_id")
                    
                    log_message(f"Unbanning old IP {ip} (created: {created_at_str}, rule_id: {rule_id}, type: {rule_type})")
                    
                    # Remove from Cloudflare (unban)
                    if rule_type == "account" and account_id:
                        delete_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/firewall/access_rules/rules/{rule_id}"
                        delete_response = requests.delete(delete_url, headers=headers, timeout=10)
                        if delete_response.status_code == 200:
                            deleted_count += 1
                            log_message(f"Unbanned {ip} from account {account_id} (account-level rule removed)")
                        else:
                            log_message(f"Failed to unban {ip} from account {account_id}: HTTP {delete_response.status_code}", "WARNING")
                    elif rule_type == "zone" and zone_id:
                        delete_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules/{rule_id}"
                        delete_response = requests.delete(delete_url, headers=headers, timeout=10)
                        if delete_response.status_code == 200:
                            deleted_count += 1
                            log_message(f"Unbanned {ip} from zone {zone_id} (zone-level rule removed)")
                        else:
                            log_message(f"Failed to unban {ip} from zone {zone_id}: HTTP {delete_response.status_code}", "WARNING")
                    
                    # Mark for removal from database
                    bans_to_remove.append(ban_key)
                    
                    time.sleep(0.05)  # Затримка для rate limiting
            except Exception as e:
                log_message(f"Error processing ban record {ban_key}: {e}", "ERROR")
                continue
        
        # Remove records from database
        for ban_key in bans_to_remove:
            if ban_key in bans_db:
                del bans_db[ban_key]
        
        # Save updated database
        if bans_to_remove:
            with open(BANS_DATABASE_FILE, "w") as f:
                json.dump(bans_db, f, indent=2)
            
            log_message(f"Unbanned {deleted_count} old IP(s) (removed {len(bans_to_remove)} records from database)")
        else:
            log_message("No old bans found to unban")
            
    except Exception as e:
        log_message(f"Error deleting old bans: {e}", "ERROR")


def parse_nginx_log_line(line: str) -> Optional[Dict]:
    """Parse nginx log line"""
    # Format: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
    pattern = r'^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    return {
        "ip": match.group(1),
        "timestamp": match.group(2),
        "method": match.group(3),
        "path": match.group(4),
        "protocol": match.group(5),
        "status": int(match.group(6)),
        "size": int(match.group(7)),
        "referer": match.group(8),
        "user_agent": match.group(9)
    }


def analyze_ip_activity(ip: str, log_entries: List[Dict]) -> Dict:
    """Analyze IP activity"""
    analysis = {
        "total_requests": len(log_entries),
        "unique_paths": set(),
        "error_404": 0,
        "error_403": 0,
        "error_400": 0,
        "sensitive_paths": [],
        "user_agents": set(),
        "is_legitimate_bot": False
    }
    
    for entry in log_entries:
        analysis["unique_paths"].add(entry["path"])
        analysis["user_agents"].add(entry["user_agent"])
        
        if entry["status"] == 404:
            analysis["error_404"] += 1
        elif entry["status"] == 403:
            analysis["error_403"] += 1
        elif entry["status"] == 400:
            analysis["error_400"] += 1
        
        # Check sensitive paths
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, entry["path"], re.IGNORECASE):
                if entry["path"] not in analysis["sensitive_paths"]:
                    analysis["sensitive_paths"].append(entry["path"])
        
        # Check legitimate bots
        if is_legitimate_bot(entry["user_agent"]):
            analysis["is_legitimate_bot"] = True
    
    analysis["unique_paths_count"] = len(analysis["unique_paths"])
    analysis["unique_user_agents_count"] = len(analysis["user_agents"])
    
    return analysis


def should_ban_ip(ip: str, analysis: Dict, abuse_confidence: Optional[int], usage_type: Optional[str]) -> Tuple[bool, str]:
    """Determine if IP should be banned"""
    reasons = []
    
    # 1. Check sensitive paths - ban immediately
    if analysis["sensitive_paths"]:
        reasons.append(f"Sensitive file access: {', '.join(analysis['sensitive_paths'][:3])}")
        return True, "; ".join(reasons)
    
    # 2. Check AbuseIPDB confidence
    if abuse_confidence is not None and abuse_confidence >= ABUSEIPDB_CONFIDENCE_THRESHOLD:
        reasons.append(f"AbuseIPDB confidence: {abuse_confidence}%")
    
    # 3. Check datacenter
    if usage_type and any(dc_type in usage_type for dc_type in DATACENTER_TYPES):
        reasons.append(f"Datacenter IP: {usage_type}")
    
    # 4. Check suspicious behavior
    if analysis["error_404"] >= MIN_404_ERRORS:
        reasons.append(f"Multiple 404 errors: {analysis['error_404']}")
    
    if analysis["unique_paths_count"] >= MIN_UNIQUE_PATHS:
        reasons.append(f"Many unique paths: {analysis['unique_paths_count']}")
    
    # If there are enough reasons - ban
    # Ban if: AbuseIPDB confidence >= threshold OR (many unique paths AND many 404) OR any other combination of reasons
    if (abuse_confidence is not None and abuse_confidence >= ABUSEIPDB_CONFIDENCE_THRESHOLD) or \
       (analysis["unique_paths_count"] >= MIN_UNIQUE_PATHS and analysis["error_404"] >= MIN_404_ERRORS) or \
       (len(reasons) >= 2):
        return True, "; ".join(reasons)
    
    return False, ""


def process_nginx_logs():
    """Process nginx logs"""
    if not os.path.exists(LOG_FILE):
        log_message(f"Log file not found: {LOG_FILE}", "ERROR")
        return
    
    # Read last 10000 lines
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            recent_lines = lines[-10000:] if len(lines) > 10000 else lines
    except Exception as e:
        log_message(f"Error reading log file: {e}", "ERROR")
        return
    
    # Group by IP
    ip_activity = defaultdict(list)
    
    for line in recent_lines:
        entry = parse_nginx_log_line(line.strip())
        if entry:
            ip_activity[entry["ip"]].append(entry)
    
    # Analyze each IP
    for ip, entries in ip_activity.items():
        # Skip IP from whitelist
        if ip in WHITELIST_IPS:
            log_message(f"IP {ip} is in whitelist - skipping")
            continue
        
        # Skip if already banned
        if is_already_banned(ip):
            continue
        
        # Check if enough requests for analysis
        if len(entries) < MIN_REQUESTS_FOR_ANALYSIS:
            continue
        
        # Check Cloudflare IP
        if is_cloudflare_ip(ip):
            log_message(f"IP {ip} is Cloudflare - skipping")
            continue
        
        # Analyze activity
        analysis = analyze_ip_activity(ip, entries)
        
        # Check legitimate bots
        if analysis["is_legitimate_bot"]:
            log_message(f"IP {ip} is legitimate bot - skipping")
            continue
        
        # Check AbuseIPDB
        abuse_confidence, usage_type, is_whitelisted = check_abuseipdb(ip)
        
        if is_whitelisted:
            log_message(f"IP {ip} is whitelisted in AbuseIPDB - skipping")
            continue
        
        # Determine if should ban
        should_ban, reason = should_ban_ip(ip, analysis, abuse_confidence, usage_type)
        
        if should_ban:
            log_message(f"BANNING IP {ip}: {reason}")
            
            # Mark as banned
            mark_as_banned(ip)
            
            # Create detailed comment for report
            comment = f"Banned by nginx-ip-monitor. {reason}. "
            comment += f"Total requests: {analysis['total_requests']}. "
            comment += f"404 errors: {analysis['error_404']}. "
            comment += f"Unique paths: {analysis['unique_paths_count']}."
            
            if analysis["sensitive_paths"]:
                comment += f" Sensitive paths: {', '.join(analysis['sensitive_paths'][:3])}."
            
            # Report to AbuseIPDB
            if report_to_abuseipdb(ip, "21", comment):
                log_message(f"Successfully reported {ip} to AbuseIPDB")
            else:
                log_message(f"Failed to report {ip} to AbuseIPDB", "ERROR")
            
            # Block in Cloudflare
            if block_in_cloudflare(ip, reason):
                log_message(f"Successfully blocked {ip} in Cloudflare")
            else:
                log_message(f"Failed to block {ip} in Cloudflare", "ERROR")
        else:
            log_message(f"IP {ip} does not meet ban criteria (requests: {analysis['total_requests']}, 404: {analysis['error_404']}, paths: {analysis['unique_paths_count']})")


def main():
    """Main function"""
    log_message("Starting nginx IP monitor")
    try:
        # First delete old bans
        delete_old_bans()
        
        # Then process new logs
        process_nginx_logs()
        log_message("nginx IP monitor completed successfully")
    except Exception as e:
        log_message(f"Error in nginx IP monitor: {e}", "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()
