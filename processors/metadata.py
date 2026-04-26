MAX_SHORT_DESCRIPTION_LENGTH = 256
MAX_LONG_DESCRIPTION_LENGTH = 1000
ALLOWED_CLASSIFICATIONS = {
    "other",
    "apt_group",
    "vulnerability",
    "data_leak",
    "malware",
    "ransomware",
    "infostealer",
    "threat_actor",
    "campaign",
    "exploit",
    "cyber_crime",
    "indicator_of_compromise",
    "ttp",
}


def build_processor_metadata(
    title, short_description, long_description, classifications, tags
):
    if len(short_description) > MAX_SHORT_DESCRIPTION_LENGTH:
        raise ValueError(
            f"Short description for {title} exceeds {MAX_SHORT_DESCRIPTION_LENGTH} characters"
        )
    if len(long_description) > MAX_LONG_DESCRIPTION_LENGTH:
        raise ValueError(
            f"Long description for {title} exceeds {MAX_LONG_DESCRIPTION_LENGTH} characters"
        )
    invalid_classifications = set(classifications) - ALLOWED_CLASSIFICATIONS
    if invalid_classifications:
        raise ValueError(
            f"Invalid classifications for {title}: {sorted(invalid_classifications)}"
        )
    if not tags:
        raise ValueError(f"Tags for {title} cannot be empty")

    return {
        "title": title,
        "short_description": short_description,
        "long_description": long_description,
        "classifications": classifications,
        "tags": tags,
    }


PROCESSOR_METADATA_BY_PROCESSOR = {
    "abuse_ch_urlhaus": build_processor_metadata(
        "abuse.ch URLhaus",
        "Malicious URLs used to distribute malware, curated by abuse.ch and Spamhaus.",
        "URLhaus is an abuse.ch and Spamhaus platform that collects, tracks, and shares malicious URLs used for malware distribution. This processor publishes recent URL indicators and related context from the URLhaus feed to support blocking, hunting, enrichment, and investigations into malware delivery infrastructure.",
        ["malware", "indicator_of_compromise", "cyber_crime"],
        ["malware-delivery", "malicious-urls", "url-intelligence", "osint"],
    ),
    "openphish": build_processor_metadata(
        "OpenPhish",
        "Public phishing URL intelligence from OpenPhish.",
        "OpenPhish provides phishing intelligence focused on timely, accurate, and relevant phishing URLs. This processor publishes URLs observed in the public OpenPhish feed to support phishing detection, takedown workflows, email and web filtering, and broader threat hunting.",
        ["indicator_of_compromise", "campaign", "cyber_crime"],
        ["phishing", "malicious-urls", "brand-abuse", "url-intelligence"],
    ),
    "abuse_ch_malwarebazaar": build_processor_metadata(
        "abuse.ch MalwareBazaar",
        "Community-shared malware samples and metadata from abuse.ch and Spamhaus.",
        "MalwareBazaar is an abuse.ch and Spamhaus platform for collecting and sharing malware samples with the security community. This processor publishes sample hashes and associated metadata from the feed so defenders and researchers can enrich detections, pivot across malware families, and investigate delivery and execution chains.",
        ["malware", "indicator_of_compromise", "cyber_crime"],
        ["malware-samples", "file-hashes", "malware-families", "sample-sharing"],
    ),
    "abuse_ch_threatfox": build_processor_metadata(
        "abuse.ch ThreatFox",
        "Community-shared malware IOCs and threat context from abuse.ch and Spamhaus.",
        "ThreatFox is an abuse.ch and Spamhaus platform for collecting and sharing indicators of compromise associated with malware, botnet command-and-control, payloads, and delivery infrastructure. This processor publishes ThreatFox indicators and related context to support detection engineering, correlation, and threat hunting.",
        ["indicator_of_compromise", "malware", "ttp"],
        ["ioc-feed", "malware-c2", "threat-hunting", "osint"],
    ),
    "ransomware_live": build_processor_metadata(
        "Ransomware.live",
        "Continuously updated ransomware victim and group intelligence from public leak sites.",
        "Ransomware.live is a free, independent platform that passively monitors ransomware groups' data leak sites and aggregates publicly disclosed victim information. This processor publishes ransomware incident intelligence derived from those public disclosures to support situational awareness, tracking of active groups, and victim-centric investigations.",
        ["ransomware", "threat_actor", "data_leak", "campaign"],
        ["ransomware-groups", "victim-tracking", "leak-sites", "extortion"],
    ),
    "certpl": build_processor_metadata(
        "CERT.PL Warning List",
        "Dangerous domains tracked by CERT Polska to protect Polish internet users.",
        "CERT Polska maintains a continuously updated warning list of dangerous websites, especially phishing domains targeting Polish internet users. This processor publishes domains from that list to support protective blocking, detection, and monitoring of campaigns aimed at credential theft and similar abuse.",
        ["indicator_of_compromise", "campaign", "cyber_crime"],
        ["phishing-domains", "domain-blocklist", "consumer-protection", "national-cert"],
    ),
    "abuse_ch_sslblacklist": build_processor_metadata(
        "abuse.ch SSLBL",
        "Malicious SSL certificates, JA3 fingerprints, and related botnet C2 infrastructure.",
        "SSLBL is an abuse.ch project focused on detecting malicious SSL connections by identifying SSL certificates, JA3 fingerprints, and related botnet command-and-control infrastructure. This processor publishes SSLBL indicators and malware associations to help detect encrypted C2 traffic and related infrastructure.",
        ["indicator_of_compromise", "malware", "ttp"],
        ["ssl-certificates", "ja3-fingerprints", "encrypted-c2", "botnet-infrastructure"],
    ),
    "blocklist_de": build_processor_metadata(
        "blocklist.de",
        "IP addresses reported for abusive activity across common internet services.",
        "blocklist.de is a community reporting service that aggregates IP addresses involved in attacks against services such as SSH, mail, FTP, and web servers, then reports abuse to network operators. This processor publishes listed IP indicators for enrichment, filtering, and monitoring of abusive infrastructure.",
        ["indicator_of_compromise", "cyber_crime"],
        ["abusive-ips", "network-abuse", "attack-sources", "service-attacks"],
    ),
    "threatview_bitcoin": build_processor_metadata(
        "ThreatView Bitcoin Feed",
        "High-fidelity malicious Bitcoin addresses from ThreatView community feeds.",
        "ThreatView publishes free community threat feeds built from public blocklists, OSINT sources, honeypots, community contributions, and ThreatView research. This processor publishes Bitcoin wallet indicators from the ThreatView feed to support ransomware tracing, crypto-related investigations, enrichment, and threat hunting.",
        ["indicator_of_compromise", "cyber_crime", "ransomware"],
        ["bitcoin-wallets", "cryptocurrency", "ransomware-payments", "wallet-intelligence"],
    ),
    "threatview_ip": build_processor_metadata(
        "ThreatView IP Feed",
        "High-fidelity malicious IP addresses from ThreatView community feeds.",
        "ThreatView publishes free community threat feeds built from public blocklists, OSINT sources, honeypots, community contributions, and ThreatView research. This processor publishes IP indicators from the ThreatView feed to support perimeter enforcement, enrichment, and threat hunting across malicious infrastructure.",
        ["indicator_of_compromise", "cyber_crime"],
        ["malicious-ips", "infrastructure", "network-defence", "blocklist"],
    ),
    "threatview_domain": build_processor_metadata(
        "ThreatView Domain Feed",
        "High-fidelity malicious domains from ThreatView community feeds.",
        "ThreatView publishes free community threat feeds built from public blocklists, OSINT sources, honeypots, community contributions, and ThreatView research. This processor publishes domain indicators from the ThreatView feed to support DNS filtering, enrichment, and threat hunting across malicious infrastructure.",
        ["indicator_of_compromise", "cyber_crime"],
        ["malicious-domains", "dns-intelligence", "infrastructure", "blocklist"],
    ),
    "threatview_sha1": build_processor_metadata(
        "ThreatView SHA1 Feed",
        "High-fidelity malicious SHA1 file hashes from ThreatView community feeds.",
        "ThreatView publishes free community threat feeds built from public blocklists, OSINT sources, honeypots, community contributions, and ThreatView research. This processor publishes SHA1 file-hash indicators from the ThreatView feed to support malware triage, enrichment, and detection of known malicious samples.",
        ["indicator_of_compromise", "malware"],
        ["sha1", "file-hashes", "malware-detection", "sample-identification"],
    ),
    "threatview_md5": build_processor_metadata(
        "ThreatView MD5 Feed",
        "High-fidelity malicious MD5 file hashes from ThreatView community feeds.",
        "ThreatView publishes free community threat feeds built from public blocklists, OSINT sources, honeypots, community contributions, and ThreatView research. This processor publishes MD5 file-hash indicators from the ThreatView feed to support malware triage, enrichment, and detection of known malicious samples.",
        ["indicator_of_compromise", "malware"],
        ["md5", "file-hashes", "malware-detection", "sample-identification"],
    ),
    "threatview_url": build_processor_metadata(
        "ThreatView URL Feed",
        "High-fidelity malicious URLs from ThreatView community feeds.",
        "ThreatView publishes free community threat feeds built from public blocklists, OSINT sources, honeypots, community contributions, and ThreatView research. This processor publishes URL indicators from the ThreatView feed to support web filtering, enrichment, and threat hunting across malicious delivery infrastructure.",
        ["indicator_of_compromise", "malware", "cyber_crime"],
        ["malicious-urls", "web-threats", "malware-delivery", "blocklist"],
    ),
    "vxvault": build_processor_metadata(
        "VXVault",
        "Malware-serving URLs observed in the VXVault feed.",
        "VXVault tracks malware samples and the URLs used to distribute them. This processor publishes URL indicators from the VXVault feed to support malware delivery detection, web filtering, and infrastructure hunting.",
        ["indicator_of_compromise", "malware", "cyber_crime"],
        ["malware-urls", "malware-delivery", "web-threats", "url-intelligence"],
    ),
    "ipsum": build_processor_metadata(
        "IPsum",
        "Aggregated bad-IP feed scored by appearances across public blocklists.",
        "IPsum is a daily feed of suspicious or malicious IP addresses aggregated from 30+ public lists and scored by the number of source-list hits. This processor publishes IPsum indicators so defenders can prioritize higher-confidence IP blocking, monitoring, and enrichment based on blacklist overlap.",
        ["indicator_of_compromise", "cyber_crime"],
        ["bad-ips", "reputation", "aggregated-blocklist", "confidence-scoring"],
    ),
    "cinsscore": build_processor_metadata(
        "CINS Score",
        "High-risk IP reputation data from the CINS threat intelligence network.",
        "CINS uses telemetry from Sentinel IPS devices and other trusted security sources to assign reputation scores to IP addresses worldwide. This processor publishes CINS-listed IP indicators to help defenders identify active attackers, scanners, and other high-risk infrastructure.",
        ["indicator_of_compromise", "cyber_crime"],
        ["ip-reputation", "high-risk-ips", "network-defence", "attack-sources"],
    ),
}
