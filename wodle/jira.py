#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-

import requests, os, sys, json, argparse, tempfile, traceback, random, time, glob
from datetime import datetime, timezone

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_PATH = os.path.join(SCRIPT_PATH, 'config.json')
JIRA_CONFIG_FILE_PATH = os.path.join(SCRIPT_PATH, 'jira-config.json')
STATE_FILE_PATH = os.path.join(SCRIPT_PATH, 'jira-state.json')
TEMP_LOG_DIR = "/tmp"
STR_CLOUD_ID = 'cloudId'
STR_EMAIL = 'AppApi-AccountEmail'
STR_API_KEY = 'AppApi-Key'
STR_LAST_TIMESTAMP = 'lastTimestamp'
STR_LAST_ID = 'lastRecordId'
STR_JIRA = 'jira'

MAX_API_RETRIES = 5
RESULTS = tempfile.TemporaryFile(mode='w+')
TEMP_LOG_FILE = None

CONFIG = None

parser = argparse.ArgumentParser(description="Export Jira audit logs.")
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
        TEMP_LOG_FILE = os.path.join(TEMP_LOG_DIR, f"jira_audit_{timestamp}.log")

        json_msg('extraction started', 'fetching Jira audit logs')

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
        for file_path in glob.glob(os.path.join(TEMP_LOG_DIR, "jira_audit_*.log")):
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
    2. Fallback to jira_config.json (Jira-specific)
    3. Raise error if neither exists
    
    Returns:
        Dict: Configuration with cloudId, email, and apiKey
    """
    config_file = None
    
    if os.path.exists(CONFIG_FILE_PATH):
        config_file = CONFIG_FILE_PATH
    elif os.path.exists(JIRA_CONFIG_FILE_PATH):
        config_file = JIRA_CONFIG_FILE_PATH
    else:
        raise FileNotFoundError(
            f"No configuration file found. Please create either:\n"
            f"  - {CONFIG_FILE_PATH} (shared with other Atlassian scripts)\n"
            f"  - {JIRA_CONFIG_FILE_PATH} (Jira-specific)\n"
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

def parse_jira_timestamp(timestamp_str):
    """Parse Jira timestamp format: 2025-11-11T15:18:38.471+0000"""
    try:
        # Jira uses +0000 format, Python expects +00:00
        # Replace timezone format to be ISO compatible
        if timestamp_str.endswith('+0000'):
            timestamp_str = timestamp_str[:-5] + '+00:00'
        elif timestamp_str.endswith('-0000'):
            timestamp_str = timestamp_str[:-5] + '-00:00'
        elif '+' in timestamp_str[-6:] and ':' not in timestamp_str[-6:]:
            # Handle other timezone formats like +0100, +0530, etc.
            tz_pos = timestamp_str.rfind('+')
            tz_part = timestamp_str[tz_pos:]
            if len(tz_part) == 5:
                timestamp_str = timestamp_str[:tz_pos] + tz_part[:3] + ':' + tz_part[3:]
        elif '-' in timestamp_str[-6:] and ':' not in timestamp_str[-6:] and 'T' not in timestamp_str[-6:]:
            tz_pos = timestamp_str.rfind('-')
            tz_part = timestamp_str[tz_pos:]
            if len(tz_part) == 5:
                timestamp_str = timestamp_str[:tz_pos] + tz_part[:3] + ':' + tz_part[3:]
        
        return datetime.fromisoformat(timestamp_str)
        
    except Exception as e:
        warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
        return datetime.now(timezone.utc)

def get_logs():
    cloud_id = dict_path(CONFIG, STR_CLOUD_ID)
    email = dict_path(CONFIG, STR_EMAIL)
    api_key = dict_path(CONFIG, STR_API_KEY)

    base_url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/auditing/record"

    auth = (email, api_key)
    headers = {"Accept": "application/json"}

    state = load_state()
    last_timestamp_str = state.get(STR_LAST_TIMESTAMP)
    last_record_id = state.get(STR_LAST_ID, 0)
    
    # Determine filtering strategy
    last_timestamp = None
    if last_timestamp_str:
        try:
            last_timestamp = parse_jira_timestamp(last_timestamp_str)
        except Exception as e:
            warning(f"Failed to parse stored timestamp, fetching recent events: {e}")
            last_timestamp = None
            last_record_id = 0
    else:
        json_msg('filtering', f'no previous state, fetching up to {args.limit} most recent events')
        last_record_id = 0

    offset = 0
    limit = 100
    events_fetched = 0
    max_records = args.limit
    new_events = []
    stop_fetching = False

    while events_fetched < max_records and not stop_fetching:
        params = {
            "offset": offset,
            "limit": min(limit, max_records - events_fetched)
        }

        retries = MAX_API_RETRIES
        while retries > 0:
            try:
                response = requests.get(base_url, auth=auth, headers=headers, params=params, timeout=60)
                response.raise_for_status()
                break
            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    fatal_error(f"HTTP 403 Forbidden: User does not have permission to access Jira audit logs.")
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
        records = data.get('records', [])
        
        if not records:
            break

        for record in records:
            created_str = record.get('created', '')
            record_id = int(record.get('id', 0))
            
            if created_str:
                try:
                    created = parse_jira_timestamp(created_str)
                    
                    # If we have a last timestamp, filter based on it
                    if last_timestamp:
                        # Skip events that are older than our last processed event
                        if created < last_timestamp:
                            stop_fetching = True
                            break
                        
                        # Skip events with same timestamp but same or lower ID
                        if created == last_timestamp and record_id <= last_record_id:
                            continue
                        
                        # This is a new event
                        if created > last_timestamp or (created == last_timestamp and record_id > last_record_id):
                            new_events.append(record)
                    else:
                        # No previous state - accept all events (up to limit)
                        new_events.append(record)
                        
                except Exception as e:
                    warning(f"Failed to process record {record_id}: {e}")

        offset += len(records)
        
        if not data.get('hasMore', False):
            break

    # Sort events by timestamp and ID
    new_events.sort(key=lambda x: (x.get('created', ''), int(x.get('id', 0))))

    # Write events
    for record in new_events:
        write_event(record)
        events_fetched += 1

def extract_relevant_user(record):
    """Extract the most relevant user from the event"""
    summary = record.get('summary', '').lower()
    author_key = record.get('authorKey', '')
    
    object_item = record.get('objectItem', {})
    associated_items = record.get('associatedItems', [])
    
    # Check if this is about a user being created/modified
    if 'user' in summary and object_item.get('typeName', '').lower() == 'user':
        return object_item.get('name', author_key)
    
    # Check associated items for user objects
    if any(keyword in summary for keyword in ['user added', 'user removed', 'user created', 'user deleted']):
        for item in associated_items:
            if isinstance(item, dict) and item.get('typeName', '').lower() == 'user':
                return item.get('name', author_key)
    
    return author_key

def write_event(record):
    """Transform Jira audit record into Wazuh-style JSON"""
    try:
        record_id = record.get('id')
        created = record.get('created')
        category = record.get('category', '')
        event_source = record.get('eventSource', '')
        summary = record.get('summary', '')
        
        author_key = record.get('authorKey', '')
        object_item = record.get('objectItem', {})
        associated_items = record.get('associatedItems', [])
        changed_values = record.get('changedValues', [])
        remote_address = record.get('remoteAddress', '')
        
        relevant_user = extract_relevant_user(record)

        converted = {
            "id": record_id,
            "timestamp": created,
            "user": relevant_user,
            "actor": author_key,
            "srcip": remote_address,
            STR_JIRA: {
                "cloudId": dict_path(CONFIG, STR_CLOUD_ID),
                "summary": summary,
                "category": category,
                "eventSource": event_source,
                "objectItem": object_item,
                "associatedItems": associated_items,
                "changedValues": changed_values
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
def update_state():
    state = load_state()
    RESULTS.seek(0)
    last_timestamp = None
    last_id = 0

    for line in RESULTS:
        event = json.loads(line)
        if 'timestamp' in event and 'id' in event:
            event_timestamp = event['timestamp']
            event_id = int(event['id'])
            
            if not last_timestamp or event_timestamp > last_timestamp:
                last_timestamp = event_timestamp
                last_id = event_id
            elif event_timestamp == last_timestamp:
                last_id = max(last_id, event_id)

    if last_timestamp:
        state[STR_LAST_TIMESTAMP] = last_timestamp
        state[STR_LAST_ID] = last_id
        save_state(state)
        json_msg('state updated', f'lastTimestamp={last_timestamp}, lastRecordId={last_id}')

def json_msg(action, description):
    msg = {
        "id": random.randint(0, 99999999999999),
        STR_JIRA: {
            "cloudId": dict_path(CONFIG, STR_CLOUD_ID),
            "action": action,
            "description": description,
        }
    }
    print(json.dumps(msg))

def fatal_error(message):
    json_msg("extraction error", message)
    sys.exit(0)

def warning(message):
    json_msg("extraction warning", message)

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        fatal_error("fatal exception :\n" + traceback.format_exc())
        