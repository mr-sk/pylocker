import os
import sys
import json
import secrets
import argparse

from math import log
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

import stdiomask
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PyLocker:
    """ PyLocker is a symmetric encryption command line locker for storing
    passwords to services. """
    def __init__(self, default_salt_bytes: int = 16, default_iterations: int = 10) -> None:
        """ Simple init, setups the arg parser and preps some member variables """
        cmd_parser = argparse.ArgumentParser(description='Decrypt locker')
        cmd_parser.add_argument('-f', '--file', help='File location to descrypt', required=True)
        args = vars(cmd_parser.parse_args())

        self.backend = default_backend()
        self.cmd_input = ''
        self.decrypted_locker_decoded = {}
        self.filename = args['file']
        self.passphrase = None

        if default_salt_bytes < 16:
            raise RuntimeError('Minimum of 16 bytes for an effective salt')
        self.default_salt_bytes = default_salt_bytes

        if default_iterations < 10:
            raise RuntimeError('Minimum of 10 iterations for an effective key derivation')
        self.default_iterations = default_iterations

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

    def password_decrypt(self, token: bytes) -> bytes:
        """ Derive the key from the passphrase, then use to decrypt the message. """
        salt, iterations, token = token.split(b'~')
        salt = b64d(salt)
        iterations = int.from_bytes(b64d(iterations), 'big')

        key = self.derive_key(salt, iterations)
        try:
            return Fernet(key).decrypt(token)
        except Exception:
            return b''

    def get_passphrase(self) -> None:
        """ Use the stdiomask library to mask the user input (hide the password). """
        self.passphrase = stdiomask.getpass(prompt='Enter passphrase: ', mask='*')

    def set_passphrase(self) -> None:
        """ Used to set the passphrase when creating a new locker; recursive """
        self.get_passphrase()
        confirmed_passphrase = stdiomask.getpass(prompt='Confirm passphrase: ', mask='*')

        if self.passphrase != confirmed_passphrase:
            print('Passphrases do not match')
            self.get_passphrase()

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
        self.cmd_input = input("[a]dd entry, [s]how-all, [q]uit or search: ").lower().strip()

    def add_entry(self) -> bool:
        """ Create the json locker entry """
        entry = {}
        locker_name = input('Locker Name: ')

        if locker_name in self.decrypted_locker_decoded:
            overwrite = input('Overwrite[Y/N]: ')
            if overwrite != 'Y':
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
            else:
                self.search()

            self.main_menu()

    def run(self) -> None:
        """ The main run loop. """
        try:
            self.load_or_create_locker()
            self.main_menu()
            self.act_on_command()
        except Exception:
            print(f'\n{type(self).__name__} failed, shutting down!')


if __name__ == '__main__':
    PyLocker().run()
