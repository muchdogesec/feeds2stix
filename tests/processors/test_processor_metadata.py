from pathlib import Path

from processors.metadata import (
    ALLOWED_CLASSIFICATIONS,
    MAX_LONG_DESCRIPTION_LENGTH,
    MAX_SHORT_DESCRIPTION_LENGTH,
    PROCESSOR_METADATA_BY_PROCESSOR,
)


PROCESSOR_FILES = {
    "abuse_ch_urlhaus": Path("processors/abuse_ch_urlhaus/urlhaus.py"),
    "openphish": Path("processors/openphish/openphish.py"),
    "phishtank": Path("processors/phishtank/phishtank.py"),
    "abuse_ch_malwarebazaar": Path("processors/abuse_ch_malwarebazaar/malwarebazaar.py"),
    "abuse_ch_threatfox": Path("processors/abuse_ch_threatfox/threatfox.py"),
    "ransomware_live": Path("processors/ransomware_live/ransomware_live.py"),
    "certpl": Path("processors/certpl/certpl.py"),
    "abuse_ch_sslblacklist": Path("processors/abuse_ch_sslblacklist/sslblacklist.py"),
    "blocklist_de": Path("processors/blocklist_de/blocklist_de.py"),
    "threatview_bitcoin": Path("processors/threatview/threatview_bitcoin/threatview_bitcoin.py"),
    "threatview_domain": Path("processors/threatview/threatview_domain/threatview_domain.py"),
    "threatview_ip": Path("processors/threatview/threatview_ip/threatview_ip.py"),
    "threatview_sha1": Path("processors/threatview/threatview_sha1/threatview_sha1.py"),
    "threatview_md5": Path("processors/threatview/threatview_md5/threatview_md5.py"),
    "threatview_url": Path("processors/threatview/threatview_url/threatview_url.py"),
    "vxvault": Path("processors/vxvault/vxvault.py"),
    "ipsum": Path("processors/ipsum/ipsum.py"),
    "cinsscore": Path("processors/cinsscore/cinsscore.py"),
}


def test_all_processor_metadata_entries_are_within_length_limits():
    for metadata in PROCESSOR_METADATA_BY_PROCESSOR.values():
        assert metadata["title"]
        assert len(metadata["short_description"]) <= MAX_SHORT_DESCRIPTION_LENGTH
        assert len(metadata["long_description"]) <= MAX_LONG_DESCRIPTION_LENGTH
        assert metadata["classifications"]
        assert set(metadata["classifications"]).issubset(ALLOWED_CLASSIFICATIONS)
        assert metadata["tags"]


def test_all_processors_expose_metadata():
    for processor_name, file_path in PROCESSOR_FILES.items():
        content = file_path.read_text()
        assert (
            f'PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["{processor_name}"]'
            in content
        )
