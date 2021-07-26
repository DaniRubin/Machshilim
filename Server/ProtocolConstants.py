#Protocol consts
PREFIX = 'M@CH'
SUFFIX = 'M@CH'
REQ_KEY = 'request'
PARAM_KEY = 'params'
RESPONSE_KEY = 'response'
DATA_KEY = 'data'
MAX_ATTAMPTES = 5
MINIMAL_REQUEST_LENGTH = 27
MINIMAL_PACKET_LENGTH = MINIMAL_REQUEST_LENGTH + len(PREFIX) + len(SUFFIX)
VALID_PACKET_PATTERN = "%s%s%s"

REQUESTS_HELP = {'100': {'name': 'Authenticate', 'Purpose': 'Authenticate user', 'Parameters': {'username':'User to log with', 'password':"The user's password"}},
'200': {'name': 'DirList', 'Purpose': 'Get the file list of the user', 'Parameters': {}},
'300': {'name': 'GetFile', 'Purpose': 'Get a specific file (base64 encoded)', 'Parameters': {'filename': "The file's name"}},
'400': {'name': 'Logout', 'Purpose': 'Logging out the connected user', 'Parameters': {}},
'777': {'name': 'Help', 'Purpose': "Get the help for the server's available requests", 'Parameters': {}}}

#Requests
REQ_AUTH = 100
REQ_DIRLIST = 200
REQ_GETFILE = 300
REQ_LOGOUT = 400
REQ_HELP = 777
AVAILABLE_REQUESTS = [REQ_AUTH, REQ_DIRLIST, REQ_GETFILE, REQ_LOGOUT, REQ_HELP]
#Responses
RESP_AUTH_SUCCESS = 101
RESP_AUTH_FAIL = 102
RESP_AUTH_KICK = 103
RESP_DIRLIST = 201
RESP_GETFILE_SUCCESS = 301
RESP_GETFILE_NOT_FOUND = 302
RESP_LOGOUT = 401
RESP_HELP = 888
RESP_GENERAL_ERR = 999
AVAILABLE_RESPONSES = [RESP_AUTH_SUCCESS, RESP_AUTH_FAIL, RESP_AUTH_KICK, RESP_DIRLIST, RESP_GETFILE_SUCCESS, RESP_GETFILE_NOT_FOUND, RESP_HELP, RESP_GENERAL_ERR]
EMPTY_RESPONSE_CONTENT = ''
#States
STATE_BREAK_CONN = 1000
STATE_BEFORE_AUTH = 2000
STATE_AFTER_AUTH = 3000
AVAILABLE_STATES = [STATE_BREAK_CONN, STATE_BEFORE_AUTH, STATE_AFTER_AUTH]