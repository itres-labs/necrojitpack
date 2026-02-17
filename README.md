# NecroJitPack: Supply Chain Necromancy Toolkit

> **⚠️ DISCLAIMER:** This toolkit is intended for **defensive security research and educational purposes only**. Do not use these tools to target repositories you do not own or have explicit authorization to test. The authors are not responsible for any misuse.

## Overview

**NecroJitPack** is a set of Python tools developed as part of the research **"Supply Chain Necromancy: Reborn Namespaces in JitPack Coordinates"**.

These tools allow researchers and DevSecOps teams to:
1.  **Scan** GitHub for `build.gradle` files referencing potentially dead or hijacked JitPack dependencies.
2.  **Verify** the status of upstream usernames (GitHub/Bitbucket) to detect available namespaces.
3.  **Analyze** the risk level of specific dependencies based on their versioning strategy (Snapshots vs. Commits).

**Full Research Paper:** [Read the Article](https://labs.itresit.es/2026/02/18/supply-chain-necromancy-reborn-namespaces-in-jitpack-coordinates/)

## 🛠️ The Tools

### 1. JitPack Scanner (`jitpack_scanner.py`)
**Discovery & Validation.**
This script acts as a "mine detector". It uses GitHub's Code Search API to find projects using JitPack dependencies (`com.github...` or `org.bitbucket...`) and validates if the upstream user still exists.

* **Target:** `build.gradle` files in the wild.
* **Detection:** Finds 404 (Dead), 301 (Redirects), and 200 (Alive) users.
* **Impact Estimation:** Queries MVNRepository to see how many artifacts depend on the dead user.

### 2. Impact Analyzer (`impact_analyzer.py`)
**Exposure Posture.**
Once a target is confirmed (e.g., `com.github.dead-user:repo`), this tool measures the "blast radius". It scans for public usages of that specific library and classifies them by risk.

* **CRITICAL:** Dynamic versions (`SNAPSHOT`, `+`, `latest`). Vulnerable to immediate RCE via repojacking.
* **HIGH:** Mutable Tags (`v1.0`). Vulnerable to cache eviction/spoofing.
* **SECURE:** Commit Hashes. Immutable.

## 🚀 Installation

### Prerequisites
* Python 3.8+
* A valid GitHub Personal Access Token (Classic)

### Setup

1.  Clone the repository:
    ```bash
    git clone [https://github.com/itresit/necrojitpack.git](https://github.com/itresit/necrojitpack.git)
    cd necrojitpack
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure your GitHub Token:**
    (Do not hardcode it. Use an environment variable).

    **Linux/Mac:**
    ```bash
    export GITHUB_TOKEN="ghp_your_token_here"
    ```

    **Windows (PowerShell):**
    ```powershell
    $env:GITHUB_TOKEN="ghp_your_token_here"
    ```

## 🕷️ Usage

### Running the Discovery Scanner
To find new vulnerable targets in the wild:

```bash
python jitpack_scanner.py
```

> **Output:** A list of users that return 404 but are still referenced in build files.

### Running the Impact Analyzer
To analyze specific targets (configure the `TARGETS` list inside the script first):

```bash
python impact_analyzer.py
```

> **Output:** A summary table classifying usage by risk level.

## 🛡️ Mitigation

If you find your project using a dead coordinate:

1.  **Pin to a specific Commit Hash:** Instead of `1.0.2`, use `a1b2c3d`.
2.  **Use Verification Metadata:** Enable Gradle's dependency verification to lock checksums.
3.  **Internal Proxy:** Cache artifacts in your own Artifactory/Nexus to avoid upstream resolution.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
