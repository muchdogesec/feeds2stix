# ThreatView Processors

This directory contains processors for converting ThreatView threat intelligence feeds to STIX 2.1 format.

## About ThreatView

ThreatView (https://threatview.io/) provides verified threat feeds for immediate perimeter enforcement across security stacks. These feeds contain high-confidence threat intelligence data including malicious IPs, domains, URLs, file hashes, and cryptocurrency wallets.

## Available Feeds

### IP Addresses
- **Feed**: [IP-High-Confidence-Feed.txt](https://threatview.io/Downloads/IP-High-Confidence-Feed.txt)
- **Processor**: `threatview_ip/threatview_ip.py`
- **Output**: IPv4 address objects with indicators
- **Documentation**: [threatview_ip/README.md](threatview_ip/README.md)

### Domains
- **Feed**: [DOMAIN-High-Confidence-Feed.txt](https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt)
- **Processor**: `threatview_domain/threatview_domain.py`
- **Output**: Domain name objects with indicators
- **Documentation**: [threatview_domain/README.md](threatview_domain/README.md)

### URLs
- **Feed**: [URL-High-Confidence-Feed.txt](https://threatview.io/Downloads/URL-High-Confidence-Feed.txt)
- **Processor**: `threatview_url/threatview_url.py`
- **Output**: URL objects with indicators
- **Documentation**: [threatview_url/README.md](threatview_url/README.md)

### MD5 Hashes
- **Feed**: [MD5-HASH-ALL.txt](https://threatview.io/Downloads/MD5-HASH-ALL.txt)
- **Processor**: `threatview_md5/threatview_md5.py`
- **Output**: File objects with MD5 hashes and indicators
- **Documentation**: [threatview_md5/README.md](threatview_md5/README.md)

### SHA1 Hashes
- **Feed**: [SHA-HASH-FEED.txt](https://threatview.io/Downloads/SHA-HASH-FEED.txt)
- **Processor**: `threatview_sha1/threatview_sha1.py`
- **Output**: File objects with SHA1 hashes and indicators
- **Documentation**: [threatview_sha1/README.md](threatview_sha1/README.md)

### Bitcoin Wallets
- **Feed**: [MALICIOUS-BITCOIN_FEED.txt](https://threatview.io/Downloads/MALICIOUS-BITCOIN_FEED.txt)
- **Processor**: `threatview_bitcoin/threatview_bitcoin.py`
- **Output**: Cryptocurrency wallet objects with indicators
- **Documentation**: [threatview_bitcoin/README.MD](threatview_bitcoin/README.MD)

## Common Usage

All ThreatView processors follow the same basic usage pattern:

```bash
# IP addresses
python processors/threatview/threatview_ip/threatview_ip.py

# Domains
python processors/threatview/threatview_domain/threatview_domain.py

# URLs
python processors/threatview/threatview_url/threatview_url.py

# MD5 hashes
python processors/threatview/threatview_md5/threatview_md5.py

# SHA1 hashes
python processors/threatview/threatview_sha1/threatview_sha1.py

# Bitcoin wallets
python processors/threatview/threatview_bitcoin/threatview_bitcoin.py
```

## Output Structure

Each processor creates STIX bundles in the following directory structure:

```
bundles/
├── threatview_ip/bundles/threatview_ip_<date>.json
├── threatview_domain/bundles/threatview_domain_<date>.json
├── threatview_url/bundles/threatview_url_<date>.json
├── threatview_md5/bundles/threatview_md5_<date>.json
├── threatview_sha1/bundles/threatview_sha1_<date>.json
└── threatview_bitcoin/bundles/threatview_bitcoin_<date>.json
```

## STIX Objects Created

All ThreatView processors create the following types of STIX objects:

1. **Identity**: Represents ThreatView as the intelligence source
2. **Marking Definition**: Contains the origin URL of the feed
3. **Observable Objects**: 
   - IPv4 addresses (`ipv4-addr`)
   - Domain names (`domain-name`)
   - URLs (`url`)
   - Files (`file`) with hash values
   - Cryptocurrency wallets (`cryptocurrency-wallet`) - custom extension
4. **Indicators**: STIX pattern-based indicators for each observable
5. **Relationships**: Links between indicators and observables

## GitHub Actions Automation

ThreatView feeds are automatically processed via GitHub Actions workflow:

- **Schedule**: Daily at 6:00 AM UTC (currently disabled, uncomment cron schedule to enable)
- **Workflow**: `.github/workflows/update-threatview.yml`
- **Manual Trigger**: Available via workflow_dispatch with feed type selection (ip, domain, url, md5, sha1, bitcoin, or all)
- **Environment**: `cyberthreatexchange-updates`

### Required Secrets

The following secrets must be configured in the GitHub repository (Settings > Secrets and variables > Actions > Environment secrets for `cyberthreatexchange-updates`):

- **`CTX_BASE_URL`**: Base URL for the CyberThreat Exchange API (e.g., `https://api.ctx.example.com`)
- **`CTX_API_KEY`**: API key for authenticating with the CyberThreat Exchange platform

### Required Variables

The following variables must be configured in the GitHub repository (Settings > Secrets and variables > Actions > Environment variables for `cyberthreatexchange-updates`):

- **`THREATVIEW_IP_FEED_ID`**: Feed ID in CTX for ThreatView IP feed
- **`THREATVIEW_DOMAIN_FEED_ID`**: Feed ID in CTX for ThreatView Domain feed
- **`THREATVIEW_URL_FEED_ID`**: Feed ID in CTX for ThreatView URL feed
- **`THREATVIEW_MD5_FEED_ID`**: Feed ID in CTX for ThreatView MD5 feed
- **`THREATVIEW_SHA1_FEED_ID`**: Feed ID in CTX for ThreatView SHA1 feed
- **`THREATVIEW_BITCOIN_FEED_ID`**: Feed ID in CTX for ThreatView Bitcoin feed
- **`MAX_BUNDLE_SIZE_KB`**: Maximum size in KB for bundle files before splitting (e.g., `10240` for 10MB)

### Manual Workflow Execution

To manually trigger the workflow:

1. Go to Actions tab in GitHub
2. Select "ThreatView Feeds to STIX Processor" workflow
3. Click "Run workflow"
4. Select feed type:
   - `all`: Process all feeds sequentially
   - `ip`: Process only IP feed
   - `domain`: Process only Domain feed
   - `url`: Process only URL feed
   - `md5`: Process only MD5 feed
   - `sha1`: Process only SHA1 feed
   - `bitcoin`: Process only Bitcoin feed

For more details about the workflow and how to trigger manual runs, see the main project documentation.

## Feed Update Schedule

The exact update schedule for ThreatView feeds is not publicly documented. The automated workflow runs daily to capture any updates.

## Requirements

All ThreatView processors require:
- Python 3.11+
- Dependencies from `requirements.txt`
- Internet connectivity to fetch feeds from threatview.io

## Support

For detailed mapping information, STIX object schemas, and examples, refer to the individual README.md files in each processor's directory.
