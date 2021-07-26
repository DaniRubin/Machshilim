# send_data Log Messages
ERR_SEND_INCOMPLETE_DATA = 'Incomplete packet was sent! %d from %d bytes.'
ERR_SEND_GENERAL = 'Unknown error while sending a packet!'

# recv_data Log Messages
ERR_RECV_FIN = 'Fin has been received!'
ERR_RECV_TIMEOUT = 'Socket got timeout while receiving'
ERR_RECV_GENERAL = 'Unknown error while receiving a packet!'

# build_general_packet Log Messages
ERR_BUILD_PACKET = 'Packet with invalid action code or data was tried to be built'

# validate_packet Log Messages
ERR_MIN_PACKET_LEN = 'Packet with less data than possible minimal has received!'
ERR_INVALID_MAGIC = 'Packet with invalid prefix or suffix has been received!'
ERR_INVALID_JSON_STRUCT = 'Packet with invalid json structure has been received!'
ERR_INVALID_JSON_CONTENT = 'Packet with invalid json content has been received!'
ERR_INVALID_REQUEST = 'Packet with invalid request code has been received!'
ERR_REQUEST_NOT_EXISTS = 'Packet with non-existing request code: %d has been received!'
ERR_INVALID_PACKET_UNKNOWN = 'Unknown error during packet validation!'

# check_user_directories Log Messgaes
ERR_USER_DIR_NOT_EXISTS = "User '%s' directory doesn't exists!"
ERR_USER_FILE_DIR_NOT_EXISTS = "Files directory doesn't exists for user: %s !"

# parse_users_xml Log Messages
ERR_USERNAME_NOT_SET = 'You have forgot to set the username for one of the users in the XML!'
ERR_PASSWORD_NOT_SET = 'Password is not set in the XML for User: %s'

# authenticate_username Log Messages
ERR_REQ_USER_NOT_FOUND = 'Requested user: %s does not exists!'
ERR_INVALID_PASS = 'The received password %s for user %s is incorrect!'

# get_getfile_content Log Messages
ERR_FILE_NOT_EXISTS = 'User %s tried to get non-existing file: %s'

# start_logic Log Messages
ERR_UNKOWN_STATE = "Unknown state was given!"
ERR_MAX_ATTEMPT_REACHED = "Shutting down connected client, max attempts has reached!."

# user_menu Log Messages
USER_REQ_HELP = 'User %s has requested Help'
USER_REQ_LOGOUT = 'User %s has logged out'
USER_REQ_DIRLIST = 'User %s has requested DirList'
USER_REQ_FILE = 'User %s get the file: %s'

# main_loop Log Messages
NEW_CONN_ACCEPTED = "Got connection from: %s"
LOG_LOGGER_INIT = "The server's logger has been initialized!"
AUTH_SUCCESS = "Authentication success with user %s!"
ENTER_MAIN_LOOP = "Enters the main loop"
WAIT_FOR_CONN = "waiting for connection..."

# validate_parameters
ROOT_DIR_NOT_EXISTS = "The selected server's root directory doesn't exists!"
