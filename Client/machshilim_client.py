import socket
import base64
import re

# HOST = '52.13.54.210'
HOST = 'localhost'
PORT = 5555
BUFSIZE = 1024
CHUNK = BUFSIZE
ADDR = (HOST, PORT)
FILE_TO_SAVE = './files/'

# before we get password
# name = '\"giggs\"'
# password = '\"Pass123\"'
# after we get password
name = '\"gportal\"'
password = '\"NicePass123\"'


# parse file content
def parse(unparsed_data):
    # parse answer
    parsed_data = re.search(r'(?<=": ").+(?=\"})', unparsed_data).group()
    # remove '\n' that are added after every 76 base64 chars
    parsed_data = parsed_data.replace('\\n', '')
    # decode base64
    parsed_data = base64.b64decode(parsed_data.encode('ascii'))
    return parsed_data
# end parse

# whole conversation
def conv(sock):
    while (1):
        req = input("enter request: \n")

        if req == 'login':
            # name = '\"' + input("please enter username: \n") + '\"'
            # password = '\"' + input("please enter password: \n") + '\"'
            query_to_send = 'M@CH{"request\":100, \"params\":{\"username\":' + name + ', \"password\":' + password + '}}M@CH'
            sock.send(query_to_send.encode())
            data = sock.recv(BUFSIZE)

        elif req == 'dir':
            sock.send('M@CH{\"request\":200, \"params\":{}}M@CH'.encode())
            data = sock.recv(BUFSIZE)

        elif req == 'readtext':
            file_name = input("please enter file name: \n")
            # file_name = 'gportal_password.txt'
            query_to_send = 'M@CH{\"request\":300, \"params\":{\"filename\":\"' + file_name + '\"}}M@CH'
            sock.send(query_to_send.encode())
            data = sock.recv(BUFSIZE)
            # parse response
            print(data)
            data = parse(data.decode())

        elif req == 'getfile':
            file_data = ''
            cur_chunk = ''
            file_name = input("please enter file name: \n")
            query_to_send = 'M@CH{\"request\":300, \"params\":{\"filename\":\"' + file_name + '\"}}M@CH'
            sock.send(query_to_send.encode())
            while True:
                print('receiving...')
                cur_chunk = sock.recv(CHUNK)
                cur_chunk = cur_chunk.decode()
                if re.search(r'("})', cur_chunk) != None: break
                file_data = file_data + cur_chunk
            file_data = file_data + cur_chunk
            # parse response
            file_data = parse(file_data)
            f = open(FILE_TO_SAVE+file_name, 'wb')
            f.write(file_data)
            f.close()
            print(f'File is written to {FILE_TO_SAVE+file_name}')

        elif req == 'logout':
            sock.send('M@CH{"params": {}, "request": 400}M@CH')
            data = sock.recv(BUFSIZE)

        else:
            print('wrong input\n')

        print(f'Received - {data}')


# endconv

def main():
    # connect to server
    sock = socket.socket()
    sock.connect(ADDR)
    print('connection successful')

    # conversation
    conv(sock)
    sock.close()


if __name__ == "__main__":
    main()
