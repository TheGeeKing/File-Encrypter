import base64
import hashlib

import PySimpleGUI as sg
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    """
    The AESCipher class is a class that uses the AES algorithm to encrypt and decrypt data.
    The class AESCipher is used to encrypt and decrypt the data.

    The class is initialized with a key.

    The class has two methods:

    encrypt: This method is used to encrypt the data.

    decrypt: This method is used to decrypt the data.

    The class has two private methods:

    _pad: This method is used to pad the data.

    _unpad: This method is used to unpad the data.
    """

    def __init__(self, key):
        """
        The function takes in a key and uses it to create a SHA256 hash digest

        :param key: The key used to encrypt the plaintext
        """
        self.bs = 16
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        """
        Encrypts the raw data using AES encryption

        :param raw: The string to be encrypted
        :return: The encrypted string.
        """
        raw = self._pad(raw.encode('utf8'))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))


    def decrypt(self, enc):
        """
        Decrypts the encrypted string using the key and returns the decrypted string

        :param enc: The encrypted password
        :return: The decrypted password.
        """
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        """
        Pad the input string with the character chr(bs - len(s) % bs) until the length of the string is
        divisible by bs

        :param s: The string to be padded
        :return: The padded string.
        """
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode('utf8')

    @staticmethod
    def _unpad(s):
        """
        Remove the padding from a plaintext string

        :param s: The string to be decrypted
        :return: The decrypted message.
        """
        return s[:-ord(s[-1:])]


def encrypt_file(file_path, content, key=''):
    """
    Encrypts the content of a file using AES encryption

    :param file_path: The path of the file to be encrypted
    :param content: The content to be encrypted
    :param key: The key is used to encrypt and decrypt the data. If no key is provided, the library will
    use the default key
    """
    cipher = AESCipher(key)
    encrypted = cipher.encrypt(content).decode()
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(encrypted)


layout = [[sg.Text('Select a file:'), sg.Input(key='-INPUT-'), sg.FileBrowse()], [sg.Text('Encryption key:'), sg.Input(key='-KEY-')],[sg.Multiline(visible=False, key='-DISPLAY-')],[sg.Button('Open', key='-OPEN-'), sg.Button('Save', visible=False, key='-SAVE-'), sg.Cancel()]]

window = sg.Window('File Encrypter').Layout(layout)

while True:
    event, values = window.Read(timeout=100)
    if event is None or event in ['Cancel', sg.WIN_CLOSED]:
        break
    elif event == '-OPEN-':
        cipher = AESCipher(values['-KEY-'])
        # This is checking if the file is empty. If it is, then it will encrypt the blank file so it can be decrypted after.
        if not len(open(values['-INPUT-'], 'r', encoding='utf-8').read()):
            encrypt_file(values['-INPUT-'], '', values['-KEY-'])
        text = cipher.decrypt(open(values['-INPUT-'], 'r', encoding='utf-8').read())
        window['-DISPLAY-'].update(text, visible=True)
        window['-SAVE-'].update(visible=True)
    elif event == '-SAVE-':
        encrypt_file(values['-INPUT-'], values['-DISPLAY-'], values['-KEY-'])
        window['-SAVE-'].update(visible=False)
        window['-DISPLAY-'].update(visible=False)
