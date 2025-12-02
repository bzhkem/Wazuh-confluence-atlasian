#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-

import requests, os, sys, json, argparse, tempfile, traceback, random, time, glob
from datetime import datetime, timedelta, timezone

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_PATH = os.path.join(SCRIPT_PATH, 'config.json')
CONFLUENCE_CONFIG_FILE_PATH = os.path.join(SCRIPT_PATH, 'confluence_config.json')
STATE_FILE_PATH = os.path.join(SCRIPT_PATH, 'confluence_state.json')
TEMP_LOG_DIR = "/tmp"
STR_CLOUD_ID = 'cloudId'
STR_EMAIL = 'email'
STR_API_KEY = 'apiKey'
STR_LAST_TIMESTAMP = 'lastTimestamp'
STR_LAST_ID = 'lastRecordId'
STR_CONFLUENCE = 'confluence'

MAX_API_RETRIES = 5
RESULTS = tempfile.TemporaryFile(mode='w+')
TEMP_LOG_FILE = None

CONFIG = None

parser = argparse.ArgumentParser(description="Export Confluence audit logs.")
parser.add_argument('--unread', '-u', dest='unread', action='store_true',
                   help='export events but keep them marked as unread')
parser.add_argument('--limit', '-l', dest='limit', type=int, default=1000,
                   help='max number of records to fetch')
args = parser.parse_args()

def main():
    global TEMP_LOG_FILE, CONFIG

    try:
        CONFIG = load_config()
        os.makedirs(TEMP_LOG_DIR, exist_ok=True)
        cleanup_old_temp_files()

        timestamp = datetime.now().strftime("%s")
        TEMP_LOG_FILE = os.path.join(TEMP_LOG_DIR, f"confluence_audit_{timestamp}.log")

        json_msg('extraction started', 'fetching Confluence audit logs')

        try:
            get_logs()
        except Exception as e:
            warning(f"Log retrieval failed: {str(e)}")
            raise

        if not args.unread:
            try:
                update_state()
            except Exception as e:
                warning(f"State update failed: {str(e)}")
                raise

        print_results()
        json_msg('extraction finished', 'extraction finished')

    except Exception as ex:
        fatal_error(f"Script failed: {str(ex)}")
    finally:
        if 'TEMP_LOG_FILE' in globals() and TEMP_LOG_FILE and os.path.exists(TEMP_LOG_FILE):
            try:
                os.remove(TEMP_LOG_FILE)
            except:
                pass

def cleanup_old_temp_files():
    """Clean up temp files older than 5 minutes"""
    try:
        now = time.time()
        for file_path in glob.glob(os.path.join(TEMP_LOG_DIR, "confluence_audit_*.log")):
            if os.path.isfile(file_path):
                file_age = now - os.path.getmtime(file_path)
                if file_age > 300:
                    os.remove(file_path)
                    json_msg('cleanup', f'deleted old temp file: {file_path}')
    except Exception as e:
        warning(f"cleanup failed: {e}")

def load_config():
    """
    Loads configuration from config files with fallback logic:
    1. Try config.json (shared with other Atlassian scripts)
    2. Fallback to confluence_config.json (Confluence-specific)
    3. Raise error if neither exists
    
    Returns:
        Dict: Configuration with cloudId, email, and apiKey
    """
    config_file = None
    
    # Try config.json first (shared config)
    if os.path.exists(CONFIG_FILE_PATH):
        config_file = CONFIG_FILE_PATH
        json_msg('config', 'using shared config.json')
    # Fallback to confluence_config.json
    elif os.path.exists(CONFLUENCE_CONFIG_FILE_PATH):
        config_file = CONFLUENCE_CONFIG_FILE_PATH
        json_msg('config', 'using confluence_config.json')
    else:
        raise FileNotFoundError(
            f"No configuration file found. Please create either:\n"
            f"  - {CONFIG_FILE_PATH} (shared with other Atlassian scripts)\n"
            f"  - {CONFLUENCE_CONFIG_FILE_PATH} (Confluence-specific)\n"
            f"Format: {{ \"cloudId\": \"...\", \"email\": \"...\", \"apiKey\": \"...\" }}"
        )
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    required_fields = [STR_CLOUD_ID, STR_EMAIL, STR_API_KEY]
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field in {config_file}: {field}")
    
    return config

def load_state():
    if not os.path.exists(STATE_FILE_PATH):
        return {}
    with open(STATE_FILE_PATH, 'r') as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE_PATH + '.tmp', 'w+') as f:
        json.dump(state, f, indent=3)
        f.write("\n")
    os.replace(f.name, STATE_FILE_PATH)

def get_logs():
    cloud_id = dict_path(CONFIG, STR_CLOUD_ID)
    email = dict_path(CONFIG, STR_EMAIL)
    api_key = dict_path(CONFIG, STR_API_KEY)
    api_url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/rest/api/audit"

    auth = (email, api_key)
    headers = {"Accept": "application/json"}

    state = load_state()
    last_timestamp_ms = state.get(STR_LAST_TIMESTAMP)
    last_record_id = state.get(STR_LAST_ID, 0)
    
    # Conversion en datetime pour affichage seulement
    if last_timestamp_ms:
        try:
            last_timestamp_ms = int(last_timestamp_ms)
            last_timestamp_dt = datetime.fromtimestamp(last_timestamp_ms / 1000, tz=timezone.utc)
            json_msg('filtering', f'fetching events after {last_timestamp_dt.isoformat()} (ID > {last_record_id})')
        except:
            last_timestamp_ms = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp() * 1000)
            last_record_id = 0
            json_msg('filtering', f'invalid timestamp in state, fetching last 24h')
    else:
        last_timestamp_ms = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp() * 1000)
        json_msg('filtering', f'no previous state, fetching last 24h')

    start = 0
    limit = 100
    events_fetched = 0
    max_records = args.limit
    new_events = []
    stop_fetching = False

    while events_fetched < max_records and not stop_fetching:
        params = {
            "start": start,
            "limit": min(limit, max_records - events_fetched)
        }

        retries = MAX_API_RETRIES
        while retries > 0:
            try:
                response = requests.get(api_url, auth=auth, headers=headers, params=params, timeout=60)
                response.raise_for_status()
                break
            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    fatal_error(f"HTTP 403 Forbidden: User does not have permission to access Confluence audit logs.")
                elif response.status_code == 401:
                    fatal_error(f"HTTP 401 Unauthorized: Invalid credentials or API token.")
                retries -= 1
                if retries > 0:
                    warning(f"API call failed, retrying... ({retries} retries left): {str(e)}")
                    time.sleep(2 ** (MAX_API_RETRIES - retries))
                else:
                    fatal_error(f"HTTP error after retries: {str(e)}")
            except Exception as e:
                retries -= 1
                if retries > 0:
                    warning(f"API call failed, retrying... ({retries} retries left): {str(e)}")
                    time.sleep(2 ** (MAX_API_RETRIES - retries))
                else:
                    fatal_error(f"Connection error after retries: {str(e)}")

        data = response.json()
        records = data.get('results', [])
        
        if not records:
            break

        for record in records:
            created_ms_str = record.get('creationDate', '')
            record_id = generate_record_id(record)
            
            if created_ms_str:
                try:
                    # Confluence timestamp est en millisecondes
                    created_ms = int(created_ms_str)
                    
                    # Comparaison en millisecondes directement
                    if created_ms > last_timestamp_ms:
                        new_events.append(record)
                    elif created_ms == last_timestamp_ms and record_id > last_record_id:
                        new_events.append(record)
                    elif created_ms < last_timestamp_ms:
                        stop_fetching = True
                        break
                        
                except Exception as e:
                    warning(f"Failed to parse timestamp: {e}")
                    if record_id > last_record_id:
                        new_events.append(record)

        start += len(records)
        events_fetched_in_batch = len(records)
        
        if events_fetched_in_batch < limit:
            break

    new_events.sort(key=lambda x: (int(x.get('creationDate', '0')), generate_record_id(x)))

    for record in new_events:
        write_event(record)
        events_fetched += 1

    json_msg('logs fetched', f'{events_fetched} new events retrieved from Confluence API')

def generate_record_id(record):
    """Generate a numeric ID from record data since Confluence audit may not have IDs"""
    created = record.get('creationDate', '')
    author = record.get('author', {}).get('publicName', '')
    summary = record.get('summary', '')
    
    id_string = f"{created}{author}{summary}"
    return abs(hash(id_string)) % (10 ** 12)

def parse_confluence_timestamp(timestamp_str):
    """Parse Confluence timestamp which can be in milliseconds or ISO format"""
    try:
        if timestamp_str.isdigit():
            return datetime.fromtimestamp(int(timestamp_str) / 1000, tz=timezone.utc)
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except:
        return datetime.now(timezone.utc)

def extract_relevant_user(record):
    """Extract the most relevant user from the event"""
    summary = record.get('summary', '').lower()
    
    author = record.get('author', {})
    author_name = author.get('publicName', '') if isinstance(author, dict) else ''
    
    associated_objects = record.get('associatedObjects', [])
    if any(keyword in summary for keyword in ['user added', 'user removed', 'user created', 'user deleted', 'user details updated']):
        for obj in associated_objects:
            if isinstance(obj, dict) and obj.get('objectType', '').lower() == 'user':
                return obj.get('name', author_name)
    if any(keyword in summary for keyword in ['page', 'blog', 'comment', 'attachment']):
        return author_name
    if 'permission' in summary:
        return author_name
    
    return author_name

def write_event(record):
    """Transform Confluence audit record into Wazuh-style JSON"""
    try:
        record_id = generate_record_id(record)
        creation_date = record.get('creationDate', '')
        
        summary = record.get('summary', '')
        category = record.get('category', '')
        remote_address = record.get('remoteAddress', '')
        
        author = record.get('author', {})
        author_name = author.get('publicName', '') if isinstance(author, dict) else ''
        
        affected_object = record.get('affectedObject', {})
        changed_values = record.get('changedValues', [])
        associated_objects = record.get('associatedObjects', [])
        
        relevant_user = extract_relevant_user(record)

        converted = {
            "id": str(record_id),
            "timestamp": creation_date,
            "user": relevant_user,
            "actor": author_name,
            "srcip": remote_address,
            STR_CONFLUENCE: {
                "cloudId": dict_path(CONFIG, STR_CLOUD_ID),
                "summary": summary,
                "category": category,
                "author": author,
                "affectedObject": affected_object,
                "associatedObjects": associated_objects,
                "changedValues": changed_values,
                "remoteAddress": remote_address
            }
        }

        json.dump(converted, RESULTS, indent=None)
        RESULTS.write("\n")

        with open(TEMP_LOG_FILE, 'a') as f:
            json.dump(converted, f, indent=None)
            f.write("\n")

    except Exception as e:
        warning(f"failed to parse event: {e}\nRecord: {record}")

def dict_path(d, *path):
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur

def print_results():
    RESULTS.seek(0)
    count = 0
    for line in RESULTS:
        print(line.strip())
        count += 1
    json_msg('events printed', f'{count} events displayed')

def update_state():
    state = load_state()
    RESULTS.seek(0)
    last_timestamp = None
    last_id = 0

    for line in RESULTS:
        event = json.loads(line)
        if 'timestamp' in event and 'id' in event:
            event_timestamp = event['timestamp']  # C'est en millisecondes!
            event_id = int(event['id'])
            
            # Comparaison correcte en millisecondes
            if not last_timestamp or int(event_timestamp) > int(last_timestamp):
                last_timestamp = event_timestamp
                last_id = event_id
            elif int(event_timestamp) == int(last_timestamp):
                last_id = max(last_id, event_id)

    if last_timestamp:
        state[STR_LAST_TIMESTAMP] = str(last_timestamp)  # Sauvegarde en millisecondes
        state[STR_LAST_ID] = last_id
        save_state(state)
        json_msg('state updated', f'lastTimestamp={last_timestamp}, lastRecordId={last_id}')

def json_msg(action, description):
    msg = {
        "id": random.randint(0, 99999999999999),
        STR_CONFLUENCE: {
            "cloudId": dict_path(CONFIG, STR_CLOUD_ID),
            "action": action,
            "description": description,
        }
    }
    print(json.dumps(msg))

def fatal_error(message):
    json_msg("extraction error", message)
    sys.exit(0) # not 1, otherwise the output will be ignored by Wazuh

def warning(message):
    json_msg("extraction warning", message)

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        fatal_error("fatal exception :\n" + traceback.format_exc())