import requests
import re

def get_technologies(url):
    """Detect technologies by analyzing HTTP headers and HTML source."""
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        html = response.text.lower()

        tech_info = {}

        # Detect Server Type
        tech_info["Server"] = headers.get("Server", "Unknown")

        # Detect CMS (WordPress, Joomla, Drupal)
        if "wp-content" in html or "wordpress" in headers.get("X-Powered-By", "").lower():
            tech_info["CMS"] = "WordPress"
        elif "joomla" in html:
            tech_info["CMS"] = "Joomla"
        elif "drupal" in html:
            tech_info["CMS"] = "Drupal"
        else:
            tech_info["CMS"] = "Unknown"

        # Detect JavaScript Libraries
        js_libraries = []
        if "jquery" in html:
            js_libraries.append("jQuery")
        if "react" in html:
            js_libraries.append("React")
        if "angular" in html:
            js_libraries.append("Angular")
        if "vue" in html:
            js_libraries.append("Vue.js")
        tech_info["JavaScript Libraries"] = js_libraries if js_libraries else "None Detected"

        # Detect PHP
        if "php" in headers.get("X-Powered-By", "").lower() or ".php" in html:
            tech_info["Backend Language"] = "PHP"
            
        elif ".aspx" in html:
            tech_info["Backend Language"] = "ASP.NET"
        elif "python" in headers.get("X-Powered-By", "").lower():
            tech_info["Backend Language"] = "Python"
        else:
            tech_info["Backend Language"] = "Unknown"

        return tech_info

    except Exception as e:
        return {"Error": str(e)}
    

def get_vulnerabilities(tech_info):
    """Fetch CVEs for detected technologies from NIST NVD (National Vulnerability Database)."""
    cve_results = {}

    for tech, version in tech_info.items():
        if version and version != "Unknown":
            search_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={tech}"
            try:
                response = requests.get(search_url, timeout=5)
                data = response.json()
                cves = data.get("result", {}).get("CVE_Items", [])
                cve_results[tech] = [cve["cve"]["CVE_data_meta"]["ID"] for cve in cves[:5]]  # Limit to 5 CVEs
            except Exception:
                cve_results[tech] = "Could not fetch CVEs"
        else:
            cve_results[tech] = "No version detected"

    return cve_results

def check_open_dirs(url):
    """Scan for common open directories that might expose sensitive information."""
    common_dirs = ["admin/", "backup/", "logs/", ".git/", "config/", "db/"]
    found_dirs = []

    for dir_path in common_dirs:
        check_url = f"{url.rstrip('/')}/{dir_path}"
        response = requests.get(check_url)
        if response.status_code == 200:
            found_dirs.append(dir_path)

    return found_dirs if found_dirs else "No open directories found"