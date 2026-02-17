import os
import re
import time
import requests
import sys
from github import Github, GithubException
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION ---
# Load token from environment variable for security
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MAX_SEARCH_RESULTS = 1000  # Max files to process
DELAY_REQUESTS = 0.5       # Delay between HTTP requests to avoid rate limiting

class JitPackScanner:
    def __init__(self, token):
        self.g = Github(token)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.checked_users = set()  # Cache to avoid redundant requests
        self.vulnerable_targets = []
        self.start_time = time.time()

    def log(self, msg, level="INFO", indent=0):
        prefix = " " * indent
        timestamp = f"[{time.strftime('%H:%M:%S')}]"
        
        colors = {
            "INFO": Fore.CYAN,
            "SCAN": Fore.BLUE,
            "CHECK": Fore.MAGENTA,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ALERT": Fore.RED + Style.BRIGHT,
            "ERROR": Fore.RED
        }
        
        color = colors.get(level, Fore.WHITE)
        icon = {
            "INFO": "[*]", "SCAN": "[?]", "CHECK": "[>]",
            "SUCCESS": "[+]", "WARNING": "[!]", "ALERT": "[!!!]", "ERROR": "[X]"
        }.get(level, "[*]")

        print(f"{color}{timestamp} {icon}{Style.RESET_ALL} {prefix}{msg}")

    def check_user_status(self, platform, username):
        """
        Verifies if the user exists on the target platform.
        Returns: DEAD, ALIVE, REDIRECT, ERROR, CACHED
        """
        cache_key = f"{platform}:{username}"
        
        if cache_key in self.checked_users:
            return "CACHED"
        
        self.checked_users.add(cache_key)
        time.sleep(DELAY_REQUESTS)

        if platform == "github":
            url = f"https://github.com/{username}"
        elif platform == "bitbucket":
            url = f"https://bitbucket.org/{username}/"
        else:
            return "UNKNOWN"

        self.log(f"Verifying status on {platform.upper()}: {username}...", "CHECK", indent=2)

        try:
            r = self.session.head(url, allow_redirects=False, timeout=10)
            
            if r.status_code == 404:
                return "DEAD"
            elif r.status_code in [301, 302]:
                return f"REDIRECT -> {r.headers.get('Location')}"
            elif r.status_code == 200:
                return "ALIVE"
            else:
                return f"STATUS_{r.status_code}"
        except Exception as e:
            self.log(f"Connection error to {url}: {e}", "ERROR", indent=2)
            return "ERROR"

    def check_artifact_usage(self, prefix, username, repo):
        """
        Checks MVNRepository for artifact usage statistics to assess impact.
        Tests multiple URL combinations due to inconsistent naming conventions.
        """
        repo_lower = repo.lower()
        
        # Possible URL variations in MVNRepository
        candidates = [
            f"{prefix}{username}/{repo}",          # com.github.User/Repo
            f"{prefix}{username}.{repo_lower}/{repo}", # com.github.User.repo/Repo
            f"{prefix}{username}/{repo_lower}"     # com.github.User/repo
        ]

        self.log(f"Assessing impact (Testing {len(candidates)} variants)...", "CHECK", indent=2)

        for path in candidates:
            url = f"https://mvnrepository.com/artifact/{path}/usages"
            
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    # Look for usage text pattern
                    usage_text = soup.find(string=re.compile(r"Used By"))
                    
                    if usage_text:
                        parent = usage_text.parent
                        num_tag = parent.find('b')
                        if num_tag:
                            impact = num_tag.text.strip()
                            self.log(f"Match found in MVN! ({path}) -> {impact} usages.", "SUCCESS", indent=4)
                            return impact
                    
                    return "DETECTED (No usage data)"

                elif r.status_code == 404:
                    continue
                    
            except Exception:
                continue

        return "0 (Not indexed)"

    def scan_github_code(self):
        """
        Searches for build.gradle files referencing JitPack dependencies from 
        GitHub or Bitbucket.
        """
        queries = [
            'filename:build.gradle "jitpack.io" "implementation" "org.bitbucket"',
            'filename:build.gradle "jitpack.io" "implementation" "com.github"'
        ]
        
        self.log("-" * 60, "INFO")
        self.log("STARTING SCAN: SEARCHING FOR VULNERABLE DEPENDENCIES", "INFO")
        self.log("-" * 60, "INFO")

        for query in queries:
            self.log(f"Executing query: {query}", "INFO")
            
            try:
                result = self.g.search_code(query)
                self.log("Query accepted. Retrieving results...", "SUCCESS")
                
                count = 0
                limit_per_query = MAX_SEARCH_RESULTS / len(queries)

                for file in result:
                    if count >= limit_per_query: 
                        self.log("Query limit reached. Moving to next...", "WARNING")
                        break
                    
                    count += 1
                    
                    # Rate Limit Handling
                    rate_limit = self.g.get_rate_limit().search
                    if rate_limit.remaining < 2:
                        reset_seconds = rate_limit.reset.timestamp() - time.time()
                        wait_time = max(60, int(reset_seconds) + 10)
                        self.log(f"Rate Limit exceeded. Sleeping for {wait_time}s...", "ALERT")
                        time.sleep(wait_time)

                    self.log(f"[{count}] Analyzing: {file.repository.full_name}", "SCAN")
                    
                    try:
                        content = file.decoded_content.decode('utf-8')
                        self.parse_gradle(content, file.html_url)
                    except Exception as e:
                        self.log(f"Read error: {e}", "ERROR")
                        
            except GithubException as e:
                self.log(f"Critical API Error: {e}", "ALERT")
                if e.status == 422:
                    self.log("Error 422: Validation Failed (Query syntax may be invalid).", "ERROR")
                    break

    def parse_gradle(self, content, source_url):
        # Captures 'com.github.User:Repo:Ver' or 'org.bitbucket...'
        pattern = r"['\"](com\.github\.|org\.bitbucket\.)([a-zA-Z0-9_\-]+)(:|/)([a-zA-Z0-9_\-]+)(:|/)([^'\"]+)['\"]"
        
        matches = re.findall(pattern, content)
        
        if not matches:
            return

        self.log(f"-> {len(matches)} JitPack dependencies found.", "INFO", indent=2)

        for match in matches:
            prefix = match[0]
            username = match[1]
            repo = match[3]
            version = match[5]
            
            platform = "github" if "github" in prefix else "bitbucket"
            full_dep = f"{prefix}{username}:{repo}:{version}"

            status = self.check_user_status(platform, username)
            
            if status == "DEAD":
                self.log(f"CONFIRMED 404: User '{username}' ({platform})", "ALERT", indent=4)
                
                impact = self.check_artifact_usage(prefix, username, repo)
                self.log(f"IMPACT ANALYSIS: Used by {impact} artifacts.", "ALERT", indent=4)
                
                self.vulnerable_targets.append({
                    'user': username,
                    'platform': platform,
                    'dep': full_dep,
                    'impact': impact,
                    'source': source_url
                })
                
            elif isinstance(status, str) and "REDIRECT" in status:
                self.log(f"REDIRECT: {username} -> {status}", "WARNING", indent=4)
            
            elif status == "ALIVE":
                self.log(f"User OK: {username}", "INFO", indent=4)

    def report(self):
        duration = time.time() - self.start_time
        print("\n" + "="*60)
        print(f"SCAN REPORT (Duration: {duration:.2f}s)")
        print("="*60)
        
        if not self.vulnerable_targets:
            print(f"{Fore.YELLOW}No vulnerable targets found in this session.")
        else:
            print(f"{Fore.RED}VULNERABLE TARGETS FOUND: {len(self.vulnerable_targets)}\n")
            for s in self.vulnerable_targets:
                print(f"{Fore.CYAN}TARGET: {s['platform']}::{s['user']}")
                print(f"  Dependency: {s['dep']}")
                print(f"  Estimated Impact: {s['impact']}")
                print(f"  Found in: {s['source']}")
                print(f"{Fore.RED}" + "-"*40)

# --- ENTRY POINT ---
if __name__ == "__main__":
    if not GITHUB_TOKEN:
        print(f"{Fore.RED}[!] ERROR: GITHUB_TOKEN environment variable is not set.")
        print(f"{Fore.YELLOW}Please export GITHUB_TOKEN='your_token_here' before running.")
        sys.exit(1)

    try:
        scanner = JitPackScanner(GITHUB_TOKEN)
        scanner.scan_github_code()
        scanner.report()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.")
        try:
            scanner.report()
        except NameError:
            pass
