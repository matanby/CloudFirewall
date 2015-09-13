# Flask app's secret key.
SECRET_KEY = 'you-will-never-ever-guess'

# System administrator username
ADMIN_USERNAME = 'fwadmin'

# System administrator password
ADMIN_PASSWORD = 'fwadmin'

# FW events in this time interval will be periodically reported to the UI.
FW_EVENTS_QUERY_INTERVAL_SECS = 60 * 10  # 10 minutes.

# FW flow data in this time interval will be periodically reported to the UI.
FW_FLOW_DATA_QUERY_INTERVAL_SECS = 60 * 1  # 1 minute.

# FW blocks and allows in this time interval will be periodically reported to the UI.
FW_BLOCKS_AND_ALLOWS_QUERY_INTERVAL_MINS = 10  # 10 minutes.

FW_SESSIONS_PER_PROTOCOL_QUERY_INTERVAL_SECS = 60 * 10  # 10 minutes
