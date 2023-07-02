import hmac
import time
import hashlib

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