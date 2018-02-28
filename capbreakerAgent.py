import os
import subprocess
from io import BytesIO
from time import sleep
from zipfile import ZipFile

import pip
from requests import RequestException

username = 'username'
password = 'password'
server = 'http://127.0.0.1'
hashcat_url = 'http://127.0.0.1/hashcat.zip'
hashcat_location = None
hashcat_mode = 3

try:
    import requests
except ImportError:
    pip.main(['install', 'requests'])
    import requests


class Hashcat:
    """ Hashcat class """

    def __init__(self, location=None, url=None, mode=3):
        self.url = url
        self.location = location
        if self.location is None:
            self.location = os.getenv('APPDATA') + '\\capbreaker'
        self.mode = mode
        self.password = None
        self.found_phrase = None
        if not os.path.isfile(self.location + '/hashcat64.exe'):
            self.download()

    def download(self):
        """ Download hashcat """
        print('Downloading hashcat.')
        request = requests.get(self.url)
        zip_file = ZipFile(BytesIO(request.content))
        zip_file.extractall(self.location)
        zip_file.close()
        print('Download completed.')

    def handshake(self, handshake):
        """ Save Handshake file in hashcat_location """
        byte_file = bytearray.fromhex('484350580400000000')
        byte_file += len(handshake['essid']).to_bytes(1, byteorder='little')
        byte_file += str.encode(handshake['essid'])
        for i in range(len(handshake['essid']), 32):
            byte_file += bytearray.fromhex('00')
        byte_file += bytearray.fromhex(handshake['keyVersion'])
        byte_file += bytearray.fromhex(handshake['keyMic'])
        byte_file += bytearray.fromhex(handshake['bssid'].replace(':', ''))
        byte_file += bytearray.fromhex(handshake['anonce'])
        byte_file += bytearray.fromhex(handshake['station'].replace(':', ''))
        byte_file += bytearray.fromhex(handshake['snonce'])
        eapol_len = int(len(handshake['eapol']) / 2)
        byte_file += eapol_len.to_bytes(2, byteorder='little')
        byte_file += bytearray.fromhex(handshake['eapol'])
        for i in range(eapol_len, 256):
            byte_file += bytearray.fromhex('00')
        new_file = open(self.location + '/hs.hccapx', 'wb')
        new_file.write(byte_file)
        new_file.close()

    def scan(self, chunk):
        """ Start scan with hashcat """
        handshake = chunk['handshake']
        self.handshake(handshake)
        self.found_phrase = (handshake['bssid'].replace(':', '') + ':').lower()
        self.found_phrase += (handshake['station'].replace(':', '') + ':').lower()
        self.found_phrase += handshake['essid']
        commands = self.location + '/hashcat64.exe ' + self.location + '/hs.hccapx' + ' -w ' + str(self.mode)
        commands += ' -m 2500 --force --potfile-disable --restore-disable --status --status-timer=20 --logfile-disable'
        for command in chunk['commands']:
            commands += ' ' + command
        process = subprocess.Popen(commands, stdout=subprocess.PIPE)
        while True:
            output = process.stdout.readline().decode()
            if not output:
                print("Hashcat exception.")
                break
            if 'Running' in output:
                requests.post(server + '/agent/keepAlive', headers={'uuid': chunk['uuid']}, auth=(username, password))
            elif 'Exhausted' in output or self.found_phrase in output:
                if self.found_phrase in output:
                    self.password = output.split(':')[4]
                process.kill()  # kill the process whether we found the phrase or not
                requests.post(server + '/agent/setResult', headers={'uuid': chunk['uuid']},
                              data={'password': hashcat.password}, auth=(username, password))
                break


if __name__ == '__main__':
    print('Cap Breaker Agent.\n')
    hashcat = Hashcat(hashcat_location, hashcat_url, hashcat_mode)
    while True:
        print('Looking for task.')
        try:
            response = requests.post(server + '/agent/getTask', auth=(username, password))
        except RequestException:
            print('Unable connect to server. please try again later.')
            break
        if response.status_code == 200:
            print('Task found, starting scan...')
            hashcat.scan(response.json())
            print('Task done')
            sleep(5)
        elif response.status_code == 204:
            print('Task not found, will try again in 60 seconds.')
            sleep(60)
        else:
            print('Unexpected error occurred.')
            break
