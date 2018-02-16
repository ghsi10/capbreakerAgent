import pip
from time import sleep

# from threading import Thread

server = "http://127.0.0.1"
hashcatLocation = "./hashcat"
mode = 3

try:
    import requests
except ImportError:
    pip.main(['install', 'requests'])
    import requests


def saveHandshake(handshake):
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
    eapolLen = int((len(handshake['eapol'].replace(" ", "")) / 2))
    byteFile += eapolLen.to_bytes(2, byteorder='little')
    byteFile += bytearray.fromhex(handshake['eapol'])
    for i in range(eapolLen, 256):
        byteFile += bytearray.fromhex('00')
    newFile = open(hashcatLocation + "/hs.hccapx", "wb")
    newFile.write(byteFile)
    newFile.close()


if __name__ == "__main__":
    # Login
    while True:
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        response = requests.post(server + "/agent/login", auth=(username, password))
        if response.status_code == 200 and response.text == "login success":
            break
        print("Invalid username and password.")
    # Get task
    while True:
        response = requests.post(server + "/agent/getNextTask", auth=(username, password))
        if response.status_code == 200:
            chunk = response.json()
            saveHandshake(chunk['handshake'])
            commands = chunk['commands']
            exit(0)
            sleep(10)
        elif response.status_code == 204:
            print("not found task")
            sleep(10)
        else:
            print("unexpected error occurred")
            exit(0)
