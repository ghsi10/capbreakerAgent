import pip
from io import BytesIO
from zipfile import ZipFile
from time import sleep

# from threading import Thread

username = "admin"
password = "admin"
server = "http://127.0.0.1"
haschatUrl = "http://caprecovery.kuchi.be/test2.zip"
hashcatLocation = "./hashcat"
mode = 3

try:
    import requests
except ImportError:
    pip.main(['install', 'requests'])
    import requests


def downloadHashcat():
    """Download hashcat"""
    request = requests.get(haschatUrl)
    zipFile = ZipFile(BytesIO(request.content))
    zipFile.extractall()
    zipFile.close()


def saveHandshake(handshake):
    """Save Handshake file in hashcatLocation"""
    byteFile = bytearray.fromhex("484350580400000000")
    essidLen = len(handshake['essid'])
    byteFile += essidLen.to_bytes(1, byteorder='little')
    byteFile += str.encode(handshake['essid'])
    for i in range(essidLen, 32):
        byteFile += bytearray.fromhex('00')
    byteFile += bytearray.fromhex(handshake['keyVersion'])
    byteFile += bytearray.fromhex(handshake['keyMic'])
    byteFile += bytearray.fromhex(handshake['bssid'].replace(":", " "))
    byteFile += bytearray.fromhex(handshake['anonce'])
    byteFile += bytearray.fromhex(handshake['station'].replace(":", " "))
    byteFile += bytearray.fromhex(handshake['snonce'])
    eapolLen = int(len(handshake['eapol']) / 2)
    byteFile += eapolLen.to_bytes(2, byteorder='little')
    byteFile += bytearray.fromhex(handshake['eapol'])
    for i in range(eapolLen, 256):
        byteFile += bytearray.fromhex('00')
    newFile = open(hashcatLocation + "/hs.hccapx", "wb")
    newFile.write(byteFile)
    newFile.close()


if __name__ == "__main__":
    # Login
    response = requests.post(server + "/agent/login", auth=(username, password))
    if response.status_code != 200 or response.text != "login success":
        while True:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            response = requests.post(server + "/agent/login", auth=(username, password))
            if response.status_code == 200 and response.text == "login success":
                print("login success")
                break
            print("Invalid username and password.")
    # Get task
    while True:
        downloadHashcat()

        response = requests.post(server + "/agent/getNextTask", auth=(username, password))
        if response.status_code == 200:
            chunk = response.json()
            saveHandshake(chunk['handshake'])
            commands = chunk['commands']
            exit(0)
            sleep(10)
        elif response.status_code == 204:
            print("not found task")
            sleep(30)
        else:
            print("unexpected error occurred")
            exit(0)
