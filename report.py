"""
report.py
Henry Nettey

This file handles how results are shown to the user.
It prints the banner, scan summary, analysis results,
and saves a JSON report.
"""

import json
import os
from datetime import datetime


def print_banner() -> None:
    """
    Prints the project title at the start of the program.
    This is just for presentation and makes the tool look clearer.
    """
    print(r"""
 _   _ _   _   _   _      _                      _    
| | | | \ | | | \ | |    | |                    | |   
| |_| |  \| | |  \| | ___| |___      _____  _ __| | __
|  _  | . ` | | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
| | | | |\  | | |\  |  __/ |_ \ V  V / (_) | |  |   < 
\_| |_|_| \_| |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\
""")
    print("=" * 70)
    print(" HENRY NETTEY - NETWORK EXPOSURE ANALYSIS TOOL")
    print(" Final Year Cybersecurity Project")
print(" What it does: Checks an IP address for open ports")
print(" Why it helps: Explains what exposed services could mean for security")
print("=" * 70)


def print_summary(ip: str, open_ports: list[dict], scan_duration: float) -> None:
    """Prints a simple summary of the scan."""
    print("\nSCAN SUMMARY")
    print("-" * 70)
    print(f"Target IP      : {ip}")
    print(f"Scan Time      : {scan_duration:.2f} seconds")
    print(f"Open Ports     : {len(open_ports)}")

    if open_ports:
        ports = [str(item["port"]) for item in open_ports]
        print(f"Ports Found    : {', '.join(ports)}")
    else:
        print("Ports Found    : None")


def print_exposure_score(score_data: dict) -> None:
    """Prints the overall exposure score."""
    print("\nEXPOSURE SCORE")
    print("-" * 70)
    print(f"Score          : {score_data['score']}/100")
    print(f"Rating         : {score_data['rating']}")


def print_analysis(results: list[dict]) -> None:
    """Prints the explanation for each open port."""
    print("\nRISK ANALYSIS")
    print("-" * 70)

    if not results:
        print("No open ports were found, so there is nothing to analyse.")
        return

    for item in results:
        print(f"Port           : {item['port']}")
        print(f"Service        : {item['service']}")
        print(f"Risk Level     : {item['risk']}")
        print(f"Explanation    : {item['reason']}")
        print(f"Advice         : {item['advice']}")
        print(f"Banner         : {item['banner']}")

        if item["banner_warnings"]:
            print("Banner Warning :")
            for warning in item["banner_warnings"]:
                print(f" - {warning}")

        print("-" * 70)


def print_risk_counts(results: list[dict]) -> None:
    """Counts how many High, Medium and Low risks were found."""
    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for item in results:
        risk = item["risk"]

        if risk in counts:
            counts[risk] += 1

    print("\nRISK SUMMARY")
    print("-" * 70)
    print(f"High Risk      : {counts['High']}")
    print(f"Medium Risk    : {counts['Medium']}")
    print(f"Low Risk       : {counts['Low']}")


def create_report_folder(output_dir: str) -> None:
    """Creates the reports folder if it does not already exist."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)


def save_json_report(
    ip: str,
    results: list[dict],
    score_data: dict,
    scan_duration: float,
    output_dir: str = "reports"
) -> str:
    """Saves the scan results into a JSON file."""
    create_report_folder(output_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_ip = ip.replace(".", "-")
    file_path = os.path.join(output_dir, f"report_{safe_ip}_{timestamp}.json")

    report_data = {
        "tool": "Henry Nettey Network Exposure Analysis Tool",
        "target_ip": ip,
        "scan_time_seconds": round(scan_duration, 2),
        "created_at": datetime.now().isoformat(),
        "exposure_score": score_data,
        "total_findings": len(results),
        "findings": results
    }

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    return file_path
