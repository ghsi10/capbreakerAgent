import pip
import os
from io import BytesIO
from zipfile import ZipFile
from time import sleep
import subprocess

username = 'admin'
password = 'admin'
server = 'https://capbreaker.herokuapp.com'
hashcatUrl = 'http://caprecovery.kuchi.be/test2.zip'
hashcatLocation = './hashcat'
mode = 3

try:
    import requests
except ImportError:
    pip.main(['install', 'requests'])
    import requests


class Hashcat:
    """ Hashcat class """

    def __init__(self, location='./hashcat', url=''):
        self.url = url
        self.location = location
        self.password = ''
        self.foundPhrase = ''
        if not os.path.isfile(self.location + '/hashcat64.exe'):
            self.download()

    def download(self):
        """ Download hashcat """
        print('Downloading hashcat.')
        request = requests.get(self.url)
        zipFile = ZipFile(BytesIO(request.content))
        zipFile.extractall(self.location)
        zipFile.close()
        print('Download completed.')

    def handshake(self, handshake):
        """ Save Handshake file in hashcatLocation """
        byteFile = bytearray.fromhex('484350580400000000')
        byteFile += len(handshake['essid']).to_bytes(1, byteorder='little')
        byteFile += str.encode(handshake['essid'])
        for i in range(len(handshake['essid']), 32):
            byteFile += bytearray.fromhex('00')
        byteFile += bytearray.fromhex(handshake['keyVersion'])
        byteFile += bytearray.fromhex(handshake['keyMic'])
        byteFile += bytearray.fromhex(handshake['bssid'].replace(':', ''))
        byteFile += bytearray.fromhex(handshake['anonce'])
        byteFile += bytearray.fromhex(handshake['station'].replace(':', ''))
        byteFile += bytearray.fromhex(handshake['snonce'])
        eapolLen = int(len(handshake['eapol']) / 2)
        byteFile += eapolLen.to_bytes(2, byteorder='little')
        byteFile += bytearray.fromhex(handshake['eapol'])
        for i in range(eapolLen, 256):
            byteFile += bytearray.fromhex('00')
        newFile = open(self.location + '/hs.hccapx', 'wb')
        newFile.write(byteFile)
        newFile.close()

    def scan(self, chunk):
        """ Start scan with hashcat """
        handshake = chunk['handshake']
        self.handshake(handshake)
        self.foundPhrase = (handshake['bssid'].replace(':', '') + ':').lower()
        self.foundPhrase += (handshake['station'].replace(':', '') + ':').lower()
        self.foundPhrase += handshake['essid']
        process = subprocess.Popen(
            'hashcat/hashcat64.exe -m 2500 -w 3 hashcat/hs.hccapx --force -a 3 05245?d?d?d', stdout=subprocess.PIPE)
        while True:
            output = process.stdout.readline().decode()
            if not output:
                print("Hashcat exeption.")
                break
            if 'Exhausted' in output or self.foundPhrase in output:
                if self.foundPhrase in output:
                    self.password = output.split(':')[4]
                    process.kill()
                requests.post(server + '/agent/setResult', headers={'uuid': chunk['uuid']},
                              data={'password': hashcat.password},
                              auth=(username, password))
                break


if __name__ == '__main__':
    print('Cap Breaker Agent.\n')
    hashcat = Hashcat(hashcatLocation, hashcatUrl)
    while True:
        print('Looking for task.')
        try:
            response = requests.post(server + '/agent/getTask', auth=(username, password))
        except:
            print('Unable connect to server. please try again later.')
            break
        if response.status_code == 200:
            print('Task found, start scan...')
            hashcat.scan(response.json())
            print('Task done')
            sleep(5)
        elif response.status_code == 204:
            print('Not found task. Trying again in 60 seconds.')
            sleep(60)
        else:
            print('Unexpected error occurred.')
            break
