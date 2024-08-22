import socket

HOST = 'localhost'
PORT = 8080


def receive(conn, flag):

    received_data = b''
    buffer_size = 4096  # Adjust based on network conditions and memory constraints
    data = b""
    while b"END" not in data:
        data = conn.recv(buffer_size)
        received_data += data

    receivedflag = received_data.split(b' ', 1)
    return receivedflag[1].rsplit(b'END')[0] if flag == receivedflag[0].decode("utf-8") else None


def translateToAnswer(received):
    res = ""
    for word in received:
        res += word
        res += " "
    return res


def connectToServer():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    return s


def sendToServer(s, message):
    s.sendall(bytes(f"{message}", "utf-8"))


def sendAsBytes(s, message):

    s.sendall(message)


def transformToLargeMessage(s, toSend):
    res = b""
    for message in toSend:
        res += message
        res += b'SEPARATOR'
    res += b'END'
    s.sendall(res)


def closeConnection(s):
    try:
        s.close()
    except ConnectionAbortedError as e:
        print(f"You logged out.")
