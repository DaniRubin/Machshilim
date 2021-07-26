################# Imports #################
import os
import sys
import time
import json
import socket
import random
import logging
import datetime
import argparse
import base64
import traceback
import threading
import xml.etree.ElementTree
from Messages import *
from ProtocolConstants import *
from ResponseMessages import *

################ Constants ################
# Socket related consts
HOST = "0.0.0.0"
MAX_MULTI_HOST = 50
BUFFER_SIZE = 536870912

VALID = True
INVALID = False

# XML related consts
XML_NAME = 'users.xml'
XML_ROOT_TAG = 'users'

# Logger consts
LOGGER_NAME = '__logger__'
LOGGER_LEVEL = logging.DEBUG
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE_DATE_PATTERN = '%Y%m%d_%H%M%S'
LOG_FILE_NAME_PATTERN = 'Server_%d_%s.log'
LOGS_PATH = os.path.join(os.getcwd(), 'Logs')


################ Classes ################
class ThreadLoggingAdapter(logging.LoggerAdapter):
    """
	Responsible for logging messages with thread id, connected host ip-address and the host source port
	"""

    def process(self, msg, kwargs):
        return '[%s, (%s:%d)] %s' % (self.extra['thread_id'], self.extra['host'], self.extra['port'], msg), kwargs


class User(object):
    def __init__(self, user_name, password):
        self.user_name = user_name
        self.password = password
        self.files_path = None

    def get_user_name(self):
        return self.user_name

    def get_files_path(self):
        return self.files_path

    def set_files_path(self, files_path):
        self.files_path = files_path

    def validate_user_creds(self, user_name, password):
        return self.user_name == user_name and self.password == password

    def get_dirlist(self):
        files = []
        file_names = os.listdir(self.files_path)
        for filename in file_names:
            cur_file_path = os.path.join(self.files_path, filename)
            cur_file_stats = os.stat(cur_file_path)
            files.append((filename, cur_file_stats.st_size))

        return files

    def get_file_content(self, filename):
        file_names = os.listdir(self.files_path)
        if filename not in file_names:
            return INVALID, None
        try:
            file_obj = open(os.path.join(self.files_path, filename), 'rb')
            file_cont = file_obj.read()
            file_obj.close()
        except Exception as err:
            print(f"get_file_content error - {err}")
            return INVALID, None

        return VALID, base64.b64encode(file_cont).decode('ascii').strip()


################ Functions ################
def printLog(log, to_print=False):
    if to_print:
        print(log)

def create_users(options):
    users_xml_path = os.path.join(options.root_dir, XML_NAME)
    users = parse_users_xml(users_xml_path)

    for user in users:
        user_name = user.get_user_name()
        if not check_user_directories(options.root_dir, user_name):
            return INVALID

        user_files_path = generate_user_paths(options.root_dir, user_name)
        user.set_files_path(user_files_path)

    return users


def get_user_by_name(users, username):
    for exists_user in users:
        if username == exists_user.get_user_name():
            return exists_user
    return None


def check_user_directories(root_dir, user_name):
    """
	check_user_directories(str, str) -> bool
	@root_dir -> The server's root directory.
	@user_name -> user name to check on.
	"""
    if not os.path.exists(os.path.join(root_dir, user_name)):
        printLog(ERR_USER_DIR_NOT_EXISTS % user_name)
        return INVALID

    files_path = generate_user_paths(root_dir, user_name)
    if not os.path.exists(files_path):
        printLog(ERR_USER_FILE_DIR_NOT_EXISTS % user_name)
        return INVALID

    return VALID


def generate_log_filename(options):
    log_date = datetime.datetime.now().strftime(LOG_FILE_DATE_PATTERN)
    log_file_name = LOG_FILE_NAME_PATTERN % (options.port, log_date)
    return log_file_name


def initialize_global_logger(options, log_file_name):
    """
	initialize_logging_handler(argparse.Namespace) -> bool
	@options -> the parsed arguments from the command line.
	"""
    try:

        # To enable Auto console logging - comment the following line
        logging.root = None

        logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(LOGGER_LEVEL)

        logger_format = logging.Formatter(fmt=LOG_FORMAT)

        if not os.path.exists(LOGS_PATH):
            os.mkdir(LOGS_PATH)
        log_path = os.path.join(LOGS_PATH, log_file_name)

        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(LOGGER_LEVEL)
        file_handler.setFormatter(logger_format)
        logger.addHandler(file_handler)

        logger.debug(LOG_LOGGER_INIT)
        return VALID

    except Exception as err:
        printLog(f"initialize_global_logger error - {err}")
        return INVALID

    return INVALID


def generate_user_paths(root_dir, user_name):
    """
	generate_user_paths(str, str) -> (str, str)
	@root_dir -> The server's root directory.
	@user_name -> user name to generate the paths for.
	"""
    files_path = os.path.join(root_dir, user_name, 'Files')
    return files_path


def parse_users_xml(xml_path):
    logger = logging.getLogger(LOGGER_NAME)
    users = []
    try:
        tree = xml.etree.ElementTree.parse(xml_path)
        root = tree.getroot()
        if XML_ROOT_TAG != root.tag:
            return INVALID

        for user in root.iter('user'):
            user_name = user.attrib.get('name')
            password = user.find('password')
            if user_name is None:
                logger.error(ERR_USERNAME_NOT_SET)
                continue
            if password is None:
                logger.warning(ERR_PASSWORD_NOT_SET % user_name)
                continue
            users.append(User(user_name, password.text))

    except Exception as err:
        printLog(f"parse_users_xml error - {err}")

    return users


def build_general_packet(response_code, data):
    """
	build_general_packet(int, str) -> str
	@response_code -> The specific code for the wanted action, can only be one of theprotocol codes.
	@data -> The packet's data, formmated as a string
	"""
    if isinstance(response_code, int) and (isinstance(data, bytes) or isinstance(data, str) or isinstance(data, dict)):
        response = {RESPONSE_KEY: response_code, DATA_KEY: data}
        json_str_response = json.dumps(response)
        return VALID_PACKET_PATTERN % (PREFIX, json_str_response, SUFFIX)

    else:
        logger = logging.getLogger(LOGGER_NAME)
        logger.debug(ERR_BUILD_PACKET)

    return None


def send_data(conn, logger_adapter, response_code, data):
    try:
        packet = build_general_packet(response_code, data)
        bytes_sent = conn.send(packet.encode())
        if bytes_sent == len(packet):
            return VALID
        else:
            logger_adapter.debug(ERR_SEND_INCOMPLETE_DATA % (bytes_sent, len(packet)))
            return INVALID

    except Exception as ex:
        printLog(f"send_data error -  {ex}")
        logger_adapter.debug(ERR_SEND_GENERAL)
        return INVALID


def recv_data(conn, logger_adapter):
    try:
        data = conn.recv(BUFFER_SIZE).decode()

        if data == "":
            logger_adapter.debug(ERR_RECV_FIN)
            return INVALID, CONN_FIN
        return VALID, data

    except socket.timeout:
        logger_adapter.debug(ERR_RECV_TIMEOUT)
        return (INVALID, CONN_TIMEOUT)

    except Exception as err:
        logger_adapter.debug(ERR_RECV_GENERAL)
        return INVALID, err


def validate_packet(logger_adapter, data):
    """
	validate_packet(str) -> bool
	@data -> recievd data from socket.
	"""
    # Checks if the packet is smaller than the minimal size of a valid packet
    if MINIMAL_PACKET_LENGTH > len(data):
        logger_adapter.debug(ERR_MIN_PACKET_LEN)
        return None

    # Extracts the protocol's header and content
    suffix = data[:4]
    prefix = data[-4:]
    content = data[4:-4]

    # Checks if the packet is signed with the unique protocol sign
    if PREFIX != prefix or SUFFIX != suffix:
        logger_adapter.debug(ERR_INVALID_MAGIC)
        return None

    try:
        json_content = json.loads(content)
    except Exception:
        logger_adapter.debug(ERR_INVALID_JSON_STRUCT)
        return None

    # Checks if the action is a valid number
    json_keys = json_content.keys()
    if REQ_KEY not in json_keys or PARAM_KEY not in json_keys:
        logger_adapter.debug(ERR_INVALID_JSON_CONTENT)
        return None

    request_code = json_content[REQ_KEY]
    params = json_content[PARAM_KEY]
    if not isinstance(request_code, int) or not isinstance(params, dict):
        logger_adapter.debug(ERR_INVALID_REQUEST)
        return None

    if request_code not in AVAILABLE_REQUESTS:
        logger_adapter.warning(ERR_REQUEST_NOT_EXISTS % request_code)
        return None

    else:
        return json_content

    logger_adapter.debug(Messages.ERR_INVALID_PACKET_UNKNOWN)
    return None


def authenticate_username(conn, logger_adapter, users, content):
    parameters = content.get(PARAM_KEY)
    recv_user_name = parameters.get('username')
    recv_password = parameters.get('password')
    if not recv_user_name or not recv_password:
        return INVALID

    if recv_user_name not in [user.get_user_name() for user in users]:
        logger_adapter.info(ERR_REQ_USER_NOT_FOUND % recv_user_name)
        return INVALID

    for user in users:
        if recv_user_name == user.get_user_name():
            if user.validate_user_creds(recv_user_name, recv_password):
                return VALID
            else:
                logger_adapter.info(ERR_INVALID_PASS % (recv_user_name, recv_password))
                return INVALID

    return INVALID


def authentication(conn, logger_adapter, users, options):
    try:
        data = recv_data(conn, logger_adapter)
        if not data[0]:
            return (STATE_BREAK_CONN, None)

        content = validate_packet(logger_adapter, data[1])
        printLog(f"Got request {content}")
        if not content:
            if not send_data(conn, logger_adapter, RESP_GENERAL_ERR, ERR_INVALID_PKT):
                return (STATE_BREAK_CONN, None)
            return (STATE_BEFORE_AUTH, None)

        if not REQ_AUTH == content.get(REQ_KEY):
            if not send_data(conn, logger_adapter, RESP_GENERAL_ERR, ERR_NOT_LOGGEDIN):
                return (STATE_BREAK_CONN, None)
            return (STATE_BEFORE_AUTH, None)

        if not authenticate_username(conn, logger_adapter, users, content):
            if not send_data(conn, logger_adapter, RESP_AUTH_FAIL, ERR_INCORRECT_CREDS):
                return (STATE_BREAK_CONN, None)
            else:
                return (STATE_BEFORE_AUTH, None)

        connected_user_name = content[PARAM_KEY].get('username')
        logger_adapter.info(AUTH_SUCCESS % connected_user_name)
        if not send_data(conn, logger_adapter, RESP_AUTH_SUCCESS, MSG_AUTH_SUCCESS % (connected_user_name)):
            return (STATE_BREAK_CONN, None)
        else:
            connected_user = get_user_by_name(users, connected_user_name)
            return (STATE_AFTER_AUTH, connected_user)

    except socket.error:
        return (STATE_BREAK_CONN, None)

    except Exception:
        return (STATE_BREAK_CONN, None)


def get_dirlist_content(conn, user, request_params):
    content = {}
    dirlist_content = user.get_dirlist()
    for filename, size in dirlist_content:
        content[filename] = size

    return RESP_DIRLIST, content


def get_getfile_content(conn, logger_adapter, user, request_params):
    if 'filename' not in request_params.keys():
        return RESP_GENERAL_ERR, ERR_INVALID_PARAM

    requested_filename = request_params.get('filename')
    status, file_content = user.get_file_content(requested_filename)
    if not status:
        logger_adapter.warning(ERR_FILE_NOT_EXISTS % (user.get_user_name(), requested_filename))
        return RESP_GETFILE_NOT_FOUND, MSG_FILE_NOT_EXISTS

    logger_adapter.info(USER_REQ_FILE % (user.get_user_name(), request_params.get('filename')))
    return RESP_GETFILE_SUCCESS, {requested_filename: file_content}


def get_logout_content(conn, user, request_params):
    return (RESP_LOGOUT, MSG_LOGOUT_SUCCESS % (user.get_user_name()))


def get_help_content(conn, user, request_params):
    return RESP_HELP, REQUESTS_HELP


def user_menu(conn, logger_adapter, connected_user, options):
    try:
        data = recv_data(conn, logger_adapter)
        if not data[0]:
            return (STATE_BREAK_CONN, None)

        printLog(f"Got request {data[1]}")

        request_content = validate_packet(logger_adapter, data[1])
        if not request_content:
            if not send_data(conn, logger_adapter, RESP_GENERAL_ERR, ERR_INVALID_PKT):
                return (STATE_BREAK_CONN, None)
            return (STATE_BEFORE_AUTH, None)

        request_code = request_content.get(REQ_KEY)
        request_params = request_content.get(PARAM_KEY)
        if REQ_DIRLIST == request_code:
            logger_adapter.info(USER_REQ_DIRLIST % connected_user.get_user_name())
            response_code, response_content = get_dirlist_content(conn, connected_user, request_params)
        elif REQ_GETFILE == request_code:
            response_code, response_content = get_getfile_content(conn, logger_adapter, connected_user, request_params)
        elif REQ_LOGOUT == request_code:
            logger_adapter.info(USER_REQ_LOGOUT % connected_user.get_user_name())
            response_code, response_content = get_logout_content(conn, connected_user, request_params)
        elif REQ_HELP == request_code:
            logger_adapter.info(USER_REQ_HELP % connected_user.get_user_name())
            response_code, response_content = get_help_content(conn, connected_user, request_params)
        else:
            response_code, response_content = RESP_GENERAL_ERR, EMPTY_RESPONSE_CONTENT

        printLog(f"Sending response with code - {response_code}")
        if not send_data(conn, logger_adapter, response_code, response_content):
            return (STATE_BREAK_CONN, None)
        if REQ_LOGOUT == request_code:
            return (STATE_BEFORE_AUTH, None)
        else:
            return (STATE_AFTER_AUTH, connected_user)

    except socket.error:
        return (STATE_BREAK_CONN, None)

    except Exception as err:
        printLog(f"user_menu error - {err}")
        return (STATE_BREAK_CONN, None)


def start_logic(conn, options, log_file_name, users):
    try:
        logger = logging.getLogger(LOGGER_NAME)
        connected_host_addr, host_src_port = conn.getpeername()
        logger_adapter = ThreadLoggingAdapter(logger, {'thread_id': threading.current_thread().ident,
                                                       'host': connected_host_addr,
                                                       'port': host_src_port})
        state = STATE_BEFORE_AUTH
        attempts = 0
        while True:

            if STATE_BEFORE_AUTH == state and MAX_ATTAMPTES >= attempts:
                state, user = authentication(conn, logger_adapter, users, options)
                if STATE_BEFORE_AUTH == state:
                    attempts += 1
                if MAX_ATTAMPTES <= attempts:
                    logger_adapter.info(ERR_MAX_ATTEMPT_REACHED)
                    attempts = 0
                    state = STATE_BREAK_CONN
                continue

            elif STATE_AFTER_AUTH == state:
                attempts = 0
                state, user = user_menu(conn, logger_adapter, user, options)
                continue

            elif STATE_BREAK_CONN == state:
                try:
                    conn.shutdown(1)
                    conn.close()
                except Exception:
                    pass

                break

            elif state not in AVAILABLE_STATES:
                logger_adapter.debug(ERR_UNKOWN_STATE)
                break

            else:
                break

    except Exception:
        try:
            conn.shutdown(1)
            conn.close()
        except Exception:
            pass


def main_loop(options, log_file_name, users):
    logger = logging.getLogger(LOGGER_NAME)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, options.port))
    s.listen(MAX_MULTI_HOST)
    while True:
        printLog(WAIT_FOR_CONN)
        conn, addr = s.accept()
        printLog(NEW_CONN_ACCEPTED % str(addr), True)
        logger.info(NEW_CONN_ACCEPTED % str(addr))
        t = threading.Thread(target=start_logic, name=None, args=(conn, options, log_file_name, users,))
        t.start()


def main():
    option_parser = argparse.ArgumentParser()
    option_parser.add_argument("-p", "--port", action="store", type=int,
                               dest="port", help="listening port")
    option_parser.add_argument("-r", "--root_dir", action="store", type=str,
                               dest="root_dir", help="root directory")

    options = option_parser.parse_args()
    log_file_name = generate_log_filename(options)
    if not initialize_global_logger(options, log_file_name):
        sys.exit()

    users = create_users(options)
    if not users:
        sys.exit()

    logger = logging.getLogger(LOGGER_NAME)
    logger.info(ENTER_MAIN_LOOP)

    main_loop(options, log_file_name, users)


if __name__ == "__main__":
    main()
