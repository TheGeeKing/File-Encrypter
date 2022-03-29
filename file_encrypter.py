import base64
import hashlib
from os.path import isfile

import PySimpleGUI as sg
from Crypto import Random
from Crypto.Cipher import AES
from win32api import GetSystemMetrics


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

sg.theme('DarkAmber')
layout = [[sg.Text('Select a file:'), sg.Input(key='-INPUT-'), sg.FileBrowse()],
          [sg.Text('Encryption key:'), sg.Input(key='-KEY-')],
          [sg.Multiline(visible=False, key='-DISPLAY-', size=(None, 5))],
          [sg.Button('Open', key='-OPEN-'), sg.Button('Close'), sg.Button('Save', visible=False, key='-SAVE-')]]


screen_size = GetSystemMetrics(0) # get the computer width size
scale_factor = screen_size / 1920 + 0.3 # get window scaling factor with the computer width size

window = sg.Window('File Encrypter', layout, resizable=True, element_justification='center', scaling=scale_factor, finalize=True)

window_state_prev = window.TKroot.state()
while True:
    event, values = window.Read(timeout=100)
    if event is None or event in ['Close', sg.WIN_CLOSED]:
        break
    elif event == '-OPEN-' and isfile(values['-INPUT-']):
        cipher = AESCipher(values['-KEY-'])
        # This is checking if the file is empty. If it is, then it will encrypt the blank file so it can be decrypted after.
        try:
            if not len(open(values['-INPUT-'], 'r', encoding='utf-8').read()):
                encrypt_file(values['-INPUT-'], '', values['-KEY-'])
        except UnicodeDecodeError:
            sg.popup_error('The file is not in UTF-8 format or is corrupted!', title='UnicodeDecodeError')
        try:
            text = cipher.decrypt(open(values['-INPUT-'], 'r', encoding='utf-8').read())
            window['-DISPLAY-'].update(text, visible=True)
            window['-SAVE-'].update(visible=True)
        except UnicodeDecodeError:
            sg.popup_error('Key is probably incorrect!', title='UnicodeDecodeError')
    elif event == '-SAVE-':
        encrypt_file(values['-INPUT-'], values['-DISPLAY-'], values['-KEY-'])
        window['-SAVE-'].update(visible=False)
        window['-DISPLAY-'].update(visible=False)

    window_state = window.TKroot.state()
    if window_state_prev == "normal" and window_state == "zoomed":
        window['-DISPLAY-'].set_size(size=(None, 55))
        window_state_prev = "zoomed"
    elif window_state_prev == "zoomed" and window_state == "normal":
        window['-DISPLAY-'].set_size(size=(None, 5))
        window_state_prev = "normal"
window.Close()
