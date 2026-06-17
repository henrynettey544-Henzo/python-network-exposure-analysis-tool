"""
main.py
This file controls the main flow of the project.
"""

import sys
import time
import ipaddress

import scanner
import analysis
import report


def validate_ip(ip_address: str) -> bool:
    """Checks if the user entered a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False


def get_target_ip() -> str:
    
    if len(sys.argv) == 2:
        target_ip = sys.argv[1]
    else:
        target_ip = input("Enter target IP address: ").strip()

    if not validate_ip(target_ip):
        print(f"\n[!] Invalid IP address: {target_ip}")
        print("[!] Example: 192.168.1.1")
        sys.exit(1)

    return target_ip


def main():
    report.print_banner()

    target_ip = get_target_ip()

    print("\n[!] Only scan systems you own or have permission to test.\n")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Scanning {len(scanner.COMMON_PORTS)} common ports...\n")

    start_time = time.time()

    open_ports = scanner.run_scan(target_ip)

    scan_duration = time.time() - start_time

    results = analysis.analyse_all(open_ports)
    score_data = analysis.calculate_exposure_score(results)

    report.print_summary(target_ip, open_ports, scan_duration)
    report.print_exposure_score(score_data)
    report.print_analysis(results)
    report.print_risk_counts(results)

    if results:
        report_path = report.save_json_report(
            ip=target_ip,
            results=results,
            score_data=score_data,
            scan_duration=scan_duration,
            output_dir="reports"
        )
        print(f"\n[+] Report saved: {report_path}")
    else:
        print("\n[*] No open ports found.")

    print("\n[*] Program finished.")


if __name__ == "__main__":
    main()
