import os
import re
import time
import sys
from github import Github, GithubException
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MAX_SEARCH_RESULTS = 200 # Per library

# CONFIRMED TARGETS (User:Repo)
TARGETS = [
    "com.github.username:repo",
    "org.bitbucket.username:repo"
]

class ImpactAnalyzer:
    def __init__(self, token):
        self.g = Github(token)
        self.results = {}

    def log(self, msg, level="INFO"):
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{color}[*] {msg}{Style.RESET_ALL}")

    def classify_risk(self, version):
        """
        Classifies risk based on version declaration.
        """
        version = version.strip()
        
        # 1. SNAPSHOTS / DYNAMIC (Immediate RCE potential)
        if "SNAPSHOT" in version or "+" in version or "latest" in version.lower():
            return "CRITICAL"
        
        # 2. COMMIT HASH (Secure - Immutable)
        # Git hashes are 40 chars, but short hashes (7-10) are also common
        if re.match(r'^[0-9a-f]{7,40}$', version):
            return "SECURE"
            
        # 3. TAGS / RELEASES (Vulnerable to Gap Bypass)
        # Anything looking like v1.0, 1.0.2, Release-1, etc.
        return "HIGH"

    def scan_impact(self):
        for target in TARGETS:
            print(f"\n{Fore.BLUE}{'='*60}")
            print(f" ANALYZING TARGET: {target}")
            print(f"{'='*60}{Style.RESET_ALL}")
            
            self.results[target] = {"CRITICAL": 0, "HIGH": 0, "SECURE": 0, "TOTAL": 0}
            
            # Exact string search in build.gradle files
            query = f'filename:build.gradle "{target}"'
            
            try:
                code_results = self.g.search_code(query)
                
                # Check rate limit before starting
                rate_limit = self.g.get_rate_limit().search
                if rate_limit.remaining < 2:
                    reset = rate_limit.reset.timestamp() - time.time()
                    self.log(f"Rate limit hit. Sleeping {int(reset)}s...", "WARNING")
                    time.sleep(max(60, reset + 10))

                # Note: totalCount is an estimate
                self.log(f"Query accepted. Searching for usages...", "INFO")
                
                count = 0
                for file in code_results:
                    if count >= MAX_SEARCH_RESULTS: 
                        break
                    
                    # Secondary rate limit check inside loop
                    if self.g.get_rate_limit().search.remaining < 2:
                        self.log("Approaching rate limit...", "WARNING")
                        time.sleep(60)

                    count += 1
                    
                    try:
                        content = file.decoded_content.decode('utf-8')
                        # Regex to capture version:
                        # implementation 'com.github.User:Repo:VERSION'
                        # Supports single and double quotes
                        pattern = f"['\"]{target}:([^'\"]+)['\"]"
                        matches = re.findall(pattern, content)
                        
                        for ver in matches:
                            risk = self.classify_risk(ver)
                            self.results[target][risk] += 1
                            self.results[target]["TOTAL"] += 1
                            
                            color = Fore.GREEN
                            if risk == "CRITICAL": color = Fore.RED
                            elif risk == "HIGH": color = Fore.MAGENTA
                            
                            print(f"   [{color}{risk}{Style.RESET_ALL}] Ver: {ver:<15} -> {file.repository.full_name}")
                            
                    except Exception as e:
                        # Encoding errors or network blips
                        continue
                    
                    # Politeness delay
                    time.sleep(1.0)
                
                if count == 0:
                     self.log("No results returned by GitHub API for this target.", "WARNING")

            except GithubException as e:
                self.log(f"GitHub API Error: {e}", "ERROR")
                time.sleep(10)

    def print_summary(self):
        print(f"\n{Fore.WHITE}{'='*80}")
        print(f"{Fore.YELLOW} VULNERABILITY SURFACE SUMMARY")
        print(f"{Fore.WHITE}{'='*80}")
        
        headers = f"{'TARGET':<40} | {'CRIT (RCE)':<12} | {'HIGH (Tag)':<12} | {'SECURE'}"
        print(headers)
        print("-" * len(headers))
        
        for target, data in self.results.items():
            line = (
                f"{target:<40} | "
                f"{Fore.RED}{data['CRITICAL']:<12}{Fore.WHITE} | "
                f"{Fore.MAGENTA}{data['HIGH']:<12}{Fore.WHITE} | "
                f"{Fore.GREEN}{data['SECURE']}"
            )
            print(line)

if __name__ == "__main__":
    if not GITHUB_TOKEN:
        print(f"{Fore.RED}[!] ERROR: GITHUB_TOKEN environment variable is not set.")
        sys.exit(1)

    print(f"{Fore.GREEN}Initializing Impact Analyzer...")
    analyzer = ImpactAnalyzer(GITHUB_TOKEN)
    
    try:
        analyzer.scan_impact()
        analyzer.print_summary()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted.")
        analyzer.print_summary()
