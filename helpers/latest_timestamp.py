import os
from datetime import datetime, timedelta
from pathlib import Path
import requests
import argparse


def find_latest_object_timestamp(args, ctx_base_url, ctx_api_key):
    file = Path(os.environ["GITHUB_OUTPUT"]).open("a")

    try:
        response = requests.get(
            f"{ctx_base_url}/v1/search/?feed_ids={args.feed_id}&page_size=1&sort=modified_descending&types={args.object_type}",
            headers={
                'accept': 'application/json',
                'API-KEY': ctx_api_key
            }
        )

        response.raise_for_status()
        data = response.json()
        timestamp = datetime.fromisoformat(data.get('objects', [{}])[0].get('modified'))
        if timestamp:
            timestamp -= timedelta(minutes=args.delta)
            timestamp = timestamp.isoformat()
            print(f"Latest indicator timestamp: {timestamp}")
            # Set output for GitHub Actions
            file.write(f"latest_timestamp={timestamp}\n")
            return timestamp
        else:
            print('No previous indicators found in feed, will process all entries')
            file.write("latest_timestamp=\n")
    except Exception as error:
        print(f"Warning: Could not fetch latest timestamp: {error}")
        print('Will use default filtering')
        file.write("latest_timestamp=\n")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch latest indicator timestamp from CTX API")
    parser.add_argument('feed_id', type=str, help='Feed ID to query for the latest indicator timestamp')
    parser.add_argument('--delta', type=int, default=0, help='Number of minutes to subtract from the latest timestamp for filtering')
    parser.add_argument('--object-type', type=str, default='indicator', help='STIX object type to filter (default: indicator)')
    args = parser.parse_args()
    
    ctx_base_url = os.getenv('CTX_BASE_URL')
    ctx_api_key = os.getenv('CTX_API_KEY')


    find_latest_object_timestamp(args, ctx_base_url, ctx_api_key)