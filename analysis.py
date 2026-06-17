"""
analysis.py
Henry Nettey

This file explains the scan results.
It takes open ports from scanner.py and adds:
- service name
- risk level
- simple explanation
- basic advice
"""

PORT_INFO = {
    21: {
        "service": "FTP",
        "risk": "High",
        "reason": "FTP can send usernames and passwords without encryption.",
        "advice": "Use SFTP or FTPS instead of normal FTP."
    },
    22: {
        "service": "SSH",
        "risk": "Medium",
        "reason": "SSH is secure when configured properly, but exposed SSH can still be targeted by brute-force attacks.",
        "advice": "Use SSH keys, disable password login, and restrict access where possible."
    },
    23: {
        "service": "Telnet",
        "risk": "High",
        "reason": "Telnet is unsafe because it sends data, including passwords, in plain text.",
        "advice": "Disable Telnet and use SSH instead."
    },
    25: {
        "service": "SMTP",
        "risk": "Medium",
        "reason": "SMTP can be abused for spam or phishing if it is misconfigured.",
        "advice": "Require authentication and stop open relay behaviour."
    },
    53: {
        "service": "DNS",
        "risk": "Medium",
        "reason": "DNS can reveal information about a network if it is badly configured.",
        "advice": "Restrict zone transfers and disable open recursion."
    },
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "reason": "HTTP is not encrypted, and web applications can contain security weaknesses.",
        "advice": "Use HTTPS and keep the web server updated."
    },
    139: {
        "service": "NetBIOS",
        "risk": "High",
        "reason": "NetBIOS can expose Windows file sharing information.",
        "advice": "Block this port from untrusted networks if it is not needed."
    },
    443: {
        "service": "HTTPS",
        "risk": "Low",
        "reason": "HTTPS is encrypted, but the web application behind it can still have issues.",
        "advice": "Keep certificates, TLS settings, and the web application updated."
    },
    445: {
        "service": "SMB",
        "risk": "High",
        "reason": "SMB is commonly targeted and should not be exposed outside trusted networks.",
        "advice": "Block SMB from the internet, disable SMBv1, and keep Windows patched."
    },
    3306: {
        "service": "MySQL",
        "risk": "High",
        "reason": "Database services should not normally be directly exposed to a network.",
        "advice": "Restrict access using firewall rules and strong authentication."
    },
    3389: {
        "service": "RDP",
        "risk": "High",
        "reason": "RDP is often targeted for brute-force attacks and ransomware access.",
        "advice": "Use VPN access, enable NLA, and restrict login attempts."
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "High",
        "reason": "An exposed database port can allow attackers to attempt login attacks.",
        "advice": "Allow access only from trusted systems."
    },
    5900: {
        "service": "VNC",
        "risk": "High",
        "reason": "VNC can expose remote desktop access and may use weak authentication.",
        "advice": "Do not expose VNC directly. Use VPN or internal access only."
    },
    8080: {
        "service": "HTTP Alternate",
        "risk": "Medium",
        "reason": "Port 8080 is often used for admin panels or development web servers.",
        "advice": "Restrict access and avoid exposing admin panels publicly."
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "High",
        "reason": "Elasticsearch can expose indexed data if authentication is not enabled.",
        "advice": "Enable authentication and restrict network access."
    },
    27017: {
        "service": "MongoDB",
        "risk": "High",
        "reason": "MongoDB should not be exposed without authentication and access control.",
        "advice": "Enable authentication and bind it to trusted interfaces only."
    }
}


UNKNOWN_PORT = {
    "service": "Unknown Service",
    "risk": "Medium",
    "reason": "This port is open, but the tool does not recognise it yet.",
    "advice": "Manually check what service is running and close it if it is not needed."
}


BANNER_WARNINGS = {
    "Apache/2.2": "This Apache version looks outdated.",
    "PHP/5": "PHP 5 is old and no longer supported.",
    "OpenSSH_6": "This OpenSSH version may be outdated.",
    "IIS/6.0": "IIS 6.0 is outdated and should be reviewed.",
    "vsftpd 2.3.4": "This vsftpd version is known to be unsafe."
}


def check_banner(banner: str) -> list[str]:
    """
    Checks the banner for simple signs of outdated software.
    This is basic and does not replace a real vulnerability scanner.
    """
    warnings = []

    if not banner or banner == "No banner received":
        return warnings

    for keyword, message in BANNER_WARNINGS.items():
        if keyword.lower() in banner.lower():
            warnings.append(message)

    return warnings


def analyse_port(port_result: dict) -> dict:
    """
    Takes one open port result and adds meaning to it.
    """
    port = port_result["port"]
    banner = port_result.get("banner", "No banner received")

    info = PORT_INFO.get(port, UNKNOWN_PORT)
    banner_warnings = check_banner(banner)

    return {
        "port": port,
        "service": info["service"],
        "risk": info["risk"],
        "reason": info["reason"],
        "advice": info["advice"],
        "banner": banner,
        "banner_warnings": banner_warnings
    }


def analyse_all(open_ports: list[dict]) -> list[dict]:
    """
    Analyses every open port found by scanner.py.
    High risk results are placed first.
    """
    results = []

    for port_result in open_ports:
        analysis = analyse_port(port_result)
        results.append(analysis)

    risk_order = {
        "High": 0,
        "Medium": 1,
        "Low": 2
    }

    return sorted(results, key=lambda item: risk_order.get(item["risk"], 3))


def calculate_exposure_score(results: list[dict]) -> dict:
    """
    Creates a simple overall exposure score.
    This gives the user a quick idea of how risky the target looks.
    """
    score = 0

    for result in results:
        if result["risk"] == "High":
            score += 15
        elif result["risk"] == "Medium":
            score += 5
        elif result["risk"] == "Low":
            score += 1

    if score > 100:
        score = 100

    if score >= 60:
        rating = "Critical"
    elif score >= 30:
        rating = "High"
    elif score >= 10:
        rating = "Medium"
    elif score > 0:
        rating = "Low"
    else:
        rating = "Minimal"

    return {
        "score": score,
        "rating": rating
    }
