import hmac
import time
import hashlib
import json
import zlib
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad 
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import padding
from datetime import datetime
import socket

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


class RequestHandler:
    def __init__(self, msg_type = '', message = None, hmac_type = 'SHA256', hmac_val = '', enc_type = 'AES256CBC') -> None:
            self.header = {
                'msg_type': msg_type,
                'crc': zlib.crc32(message.encode()) if message else 0, #use zlib ibrary to 
                'timestamp': str(datetime.now())
            }
            self.message = message
            self.hmac = {
                'hmac_type': hmac_type,
                'hmac_val': hmac_val
            }
            self.enc_type = enc_type

    def append_to_header(self, key = '', value = ''):
        self.header[key] = value

    def build_request(self, hmac_key = ''):
        msg_obj = {'header': self.header, 'message': self.message, 'security': {'enc_type': self.enc_type}}
        self.hmac['hmac_val'] = hmac.new(hmac_key.encode(), json.dumps(msg_obj).encode(), hashlib.sha256).hexdigest()
        msg_obj['security']['hmac'] = self.hmac
        return msg_obj


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
    
     #Function for generation shared key. p and g are prime and primitive numbers.
    def generate_shared_key(self, for_client = False):
        p = 89381270863332931872159944476876498042528716480323987919416299827681815950961
        g = 38206302734509127934494184288146126895979393772837750277878652743093783496073
        self.private_key = number.getRandomInteger(32)
        self.shared_key = int(pow(g,self.private_key,p))

    def generate_keys(self, other_shared_key, for_client = False):
        # Generate the DHSK and enc_type using diffie-hellman algorithm

        p = 89381270863332931872159944476876498042528716480323987919416299827681815950961
        
        self.dhsk = bytes(str(pow(other_shared_key, self.private_key, p)), 'utf-8')

        h = hmac.new(self.dhsk, self.friend['password'].encode('utf-8') if for_client else self.password.encode('utf-8'), digestmod=hashlib.sha256)
        self.enc_type = h.hexdigest()
        #print(self.enc_type)

        # Generate the IV using SHA256
        self.iv = Client.generate_digest(self.enc_type)[:16]
        #print(self.iv)

        # Generate the HMAC_KEY using SHA256
        self.hmac_key = Client.generate_digest(self.iv)
        #print(self.hmac_key)

        # Generate the CHAP_SECRET using SHA256
        self.chap_secret = Client.generate_digest(self.hmac_key)
        #print(self.chap_secret)
    
    def encrypt_message(self,message): #for encrypting the msg by python documentation
        #here there should be msg
        #this should be dhsk key of 32 bytes
        cipher = AES.new(self.dhsk[:32], AES.MODE_CBC, bytes(self.iv, 'utf-8'))
        message = bytes(message,'utf-8')

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message)
        padded_data += padder.finalize()

        ct_bytes = cipher.encrypt(padded_data)

        return (b64encode(ct_bytes).decode('utf-8'))
    
    def decrypt_message(self,message):
        body = b64decode(message)
        cipher = AES.new(self.dhsk[:32], AES.MODE_CBC, bytes(self.iv, 'utf-8'))
        pt = cipher.decrypt(body) 
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(pt)
        data += unpadder.finalize()
        
        return data.decode('utf-8')
    
    def send_message(self, recipient, message, skip_directory_check = False):

        if not skip_directory_check:
            self.friend = self.get_user_info(recipient, 'username')
        if self.friend:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                self.channel = client
                to_address = self.friend['ip'], self.friend['port']
                try:
                    self.channel.connect(to_address)
                    self.encrypted_and_log(Logger.info, 'Opened client socket.')
                except ConnectionRefusedError:
                    self.encrypted_and_log(Logger.warning, f'Connection refused :: {self.friend["username"]} is offline. Closing socket.')
                    print(f'Connection refused :: {self.friend["username"]} is offline!')
                    return
                except Exception as e:
                    self.encrypted_and_log(Logger.error, str(e))
                    print(e)
                    return

                # generate shared key
                self.generate_shared_key(True)
                # sending shared key
                req = RequestHandler(msg_type = 'response', message = str(self.shared_key)).build_request()
                self.channel.sendall(json.dumps(req).encode('utf-8'))
                self.encrypted_and_log(Logger.info, 'Sent shared key.')

                # waiting for shared key from other side
                t = time.time()
                while True:
                    if time.time() - t > 10:
                        self.encrypted_and_log(Logger.error, 'Response timed out. Did not receive shared key. Closing socket.')
                        print('No response in 10s. Could not exchange keys.')
                        return # close socket
                    
                    if response := self.channel.recv(1024):
                        response = json.loads(response.decode())
                        if server_shared_key := response['message']:
                            self.encrypted_and_log(Logger.info, 'Received shared key.')
                            # generate keys
                            self.generate_keys(int(server_shared_key), True)
                            break

                self.encrypted_and_log(Logger.info, 'Starting handshake.')

                # sending hello message
                req = RequestHandler(msg_type = 'hello')
                req.append_to_header('username', self.username)
                self.channel.sendall(json.dumps(req.build_request(self.hmac_key)).encode('utf-8'))
                self.encrypted_and_log(Logger.info, 'Hello message sent.')

                # waiting for challenge
                t = time.time()
                while True:
                    if time.time() - t > 10:
                        self.encrypted_and_log(Logger.error, 'Response timed out. Closing socket.')
                        print("No response received in 10 seconds. Closing socket.")
                        return # close socket

                    if response := self.channel.recv(1024):
                        response = json.loads(response.decode())
                        if Client.check_message_integrity(response):
                            if response['header']['msg_type'] == 'challenge':
                                self.encrypted_and_log(Logger.info, 'Received challenge message.')
                                decrypted_challenge = self.decrypt_message(response['message'])
                                challenge_message = self.encrypt_message(Client.generate_digest(decrypted_challenge + self.chap_secret))
                                req = RequestHandler(msg_type = 'response', message = challenge_message).build_request(self.hmac_key)
                                self.channel.sendall(json.dumps(req).encode('utf-8'))
                                self.encrypted_and_log(Logger.info, 'Responded to challenge.')
                                break
                        else:
                            self.encrypted_and_log(Logger.error, 'Integrity of received challenge message compromised. Closing socket.')
                            print('Message integrity compromised!')
                            return

                # Wait for ack or nack message
                t = time.time()
                challenge = ''
                while True:
                    if (time.time() - t) > 10:
                        self.encrypted_and_log(Logger.error, 'Response timed out. Closing socket')
                        print("No response received in 10 seconds. Closing socket.")
                        return # close socket

                    if response:= self.channel.recv(1024):
                        response = json.loads(response.decode())
                        if Client.check_message_integrity(response):
                            if response['header']['msg_type'] == 'ack':
                                self.encrypted_and_log(Logger.info, 'Acknowledgement received.')
                                # sending challenge
                                challenge = Client.generate_digest(str(time.time()))
                                enc_challenge = self.encrypt_message(challenge)
                                req = RequestHandler(msg_type = 'challenge', message = enc_challenge).build_request(self.hmac_key)
                                self.channel.sendall(json.dumps(req).encode('utf-8'))
                                self.encrypted_and_log(Logger.info, 'Challenge sent.')
                                break
                            if response['header']['msg_type'] == 'nack':
                                self.encrypted_and_log(Logger.error, 'Handshake failed. Closing socket.')
                                print('Handshake failed.')
                                return # close socket
                        else:
                            self.encrypted_and_log(Logger.error, 'Integrity of ack compromised. Closing socket.')
                            print('Message integrity compromised!')
                            return

                # waiting for challenge response
                t = time.time()
                while True:
                    if time.time() - t > 10:
                        self.encrypted_and_log(Logger.error, 'Response timed out. Closing socket.')
                        print("No response received in 10 seconds. Closing socket.")
                        return # close socket

                    if response := self.channel.recv(1024):
                        response = json.loads(response.decode())
                        if Client.check_message_integrity(response):
                            if response['header']['msg_type'] == 'response':
                                self.encrypted_and_log(Logger.info, 'Received response to challenge.')
                                expected_response = Client.generate_digest(challenge + self.chap_secret)
                                actual_response = self.decrypt_message(response['message'])
                                if expected_response == actual_response:
                                    # Send an ack message to the client
                                    ack = RequestHandler(msg_type = 'ack').build_request(self.hmac_key)
                                    self.channel.sendall(json.dumps(ack).encode('utf-8'))
                                    self.encrypted_and_log(Logger.info, 'Acknowledged response to challenge.')
                                    break
                                else:
                                    self.encrypted_and_log(Logger.error, 'Handshake failed. Closing socket.')
                                    print("Handshake failed.")
                                    # Send a nack message to the client
                                    nack = RequestHandler(msg_type = 'nack').build_request(self.hmac_key)
                                    self.channel.sendall(json.dumps(nack).encode('utf-8'))
                                    self.encrypted_and_log(Logger.info, 'Nack sent.')
                                    return # close socket
                        else:
                            self.encrypted_and_log(Logger.error, 'Integrity of response to challenge compromised. Closing socket.')
                            print('Message integrity compromised!')
                            return


                # waiting for response
                t = time.time()
                while True:
                    if time.time() - t > 10:
                        self.encrypted_and_log(Logger.error, 'Response timed out. Closing socket.')
                        print("No response received in 10 seconds. Closing socket.")
                        return # close socket

                    if response := self.channel.recv(1024):
                        response = json.loads(response.decode())
                        if Client.check_message_integrity(response):
                            if response['header']['msg_type'] == 'response':
                                self.encrypted_and_log(Logger.info, 'Handshake successful.')
                                print("Handshake successful.")
                                break
                            else:
                                self.encrypted_and_log(Logger.error, 'Handshake failed. Closing socket.')
                                print('Handshake failed.')
                                return
                        else:
                            self.encrypted_and_log(Logger.error, 'Message integrity compromised. Handshake failed. Closing socket.')
                            print('Message integrity compromised!')
                            return

                # sending message
                req = RequestHandler(msg_type = 'response', message = self.encrypt_message(message)).build_request(self.hmac_key)
                self.channel.sendall(json.dumps(req).encode('utf-8'))
                info = ' | '.join([self.friend['username'], str(self.friend['ip']), str(self.friend['port'])])
                self.encrypted_and_log(Logger.info, f'Message sent to {info}')
                self.encrypted_and_log(Logger.info, message)
        else:
            self.encrypted_and_log(Logger.error, 'Recipient does not exist.')
            print('Recipient does not exist in the directory!')
            try_again = input('Do you want to mannually connect (Y)es or (N)o: ').lower()
            if try_again == 'y':
                self.attempt_manual_connection(recipient, message)
            else:
                print('Closing socket.')
                self.encrypted_and_log(Logger.info, 'Closing socket')
    