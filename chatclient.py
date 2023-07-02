import hmac
import time
import hashlib
import json
import zlib

class Logger:
    # message priority levels
    info, warning, error = 3, 2, 1

    def __init__(self, password = '', file_name = '') -> None:
        self.password = password
        self.file_name = file_name or f'{int(time.time())}.txt'
        self.error_logs_file = f'{self.file_name.split(".")[0]}_errors.txt'

    #All the messages sent and received are logged to a file securely using SHA256 and HMAC.
    def encrypted_and_log(self, level = info, message = ''):
        encrypted_message = hmac.new(self.password.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
        log = f'{int(time.time())}::{level}::{message}::{encrypted_message}' #Log format
        with open(self.file_name, 'a+') as file:
            file.write(log + '\n')

    #Function is used to verify logs which are being logged.
    def verify_logs(self):
        error_logs = []
        with open(self.file_name, 'r') as file:
            if log := file.readline().strip():
                timestamp, level, message, encrypted_message = log.split('::')
                new_hmac = hmac.new(self.password.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
                if new_hmac != encrypted_message:
                    error_logs.append(f'{timestamp}::{level}::{message}::{encrypted_message}::{new_hmac}')

        with open(self.error_logs_file, 'a+') as file:
            for log in error_logs:
                file.write(log + '\n')


class Client(Logger):

    def __init__(self, port, file_path) -> None:
        self.recipient_directory = Client.load_user_directory(file_path)
        self.friend = None
        if user := self.get_user_info(port, 'port'):
            self.username = user['username']
            self.password = user['password']
            self.port = user['port']
            self.ip = user['ip']
            self.channel = None
            self.private_key = None
            self.shared_key = None
            Logger.__init__(self, self.password, f'{self.username}_{self.port}.txt')
        else:
            raise Exception("The username does not exist in the directory!")

    # load user directory from file
    @staticmethod
    def load_user_directory(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def get_user_info(self, check = None, key = ''):
        try:
            for recipient in self.recipient_directory:
                if recipient[key] == check:
                    return recipient
                if type(check) is str and recipient[key].lower() == check.lower():
                    return recipient
        except KeyError as e:
            print('key not present in directory.', e)

    @staticmethod
    def check_message_integrity(response):
        excepted_crc = response['header']['crc']
        message_crc = zlib.crc32(response['message'].encode()) if response['message'] else 0
        return excepted_crc == message_crc
    
    @staticmethod
    def generate_digest(msg = ''):
        h = hashlib.sha256()
        h.update(msg.encode())
        return h.hexdigest()