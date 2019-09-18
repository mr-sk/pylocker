import argparse
import json
import os
import secrets
import stdiomask
import sys

from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PyLocker:
    """ PyLocker is a symmetric encryption command line locker for storing passwords to services.
    """
    def __init__(self):
        """ Simple init, setups the arg parser and preps some member variables """
        cmd_parser = argparse.ArgumentParser(description='Decrypt locker')
        cmd_parser.add_argument('-f', '--file', help='File location to descrypt', required=True)
        args = vars(cmd_parser.parse_args())

        self.backend = default_backend()
        self.cmd_input = ''
        self.decrypted_locker_decoded = []
        self.filename = args['file']
        self.passphrase = None

    def derive_key(self, password: bytes, salt: bytes, iterations: int) -> bytes:
        """ Also known as key stretching, we compute the key with a salt and
        any number of iterations to generate a derived key. """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend)
        return b64e(kdf.derive(password))

    def password_encrypt(self, message: bytes, password: str, iterations: int) -> bytes:
        """ Symmetric encryption leveraging Fernet. Use the salt and iterations to encrypt
        the message. """
        salt = secrets.token_bytes(16)
        key = self.derive_key(password.encode(), salt, iterations)
        return b64e(
            b'%b%b%b' % (
                salt,
                iterations.to_bytes(4, 'big'),
                b64d(Fernet(key).encrypt(message)),
            )
        )

    def password_decrypt(self, token: bytes) -> str:
        """ Derive the key from the passphrase, then use to decrypt the message. """
        decoded = b64d(token)
        salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
        iterations = int.from_bytes(iter, 'big')
        key = self.derive_key(self.passphrase.encode(), salt, iterations)

        try:
            return Fernet(key).decrypt(token)
        except:
            return ''

    def get_passphrase(self):
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

            with open(self.filename) as f:
                encrypted_contents = f.read().encode()

            decrypted_locker = self.password_decrypt(encrypted_contents)
            if decrypted_locker is '':
                print("Invalid token, exiting")
                sys.exit()

            self.decrypted_locker_decoded = json.loads(decrypted_locker.decode('utf-8'))
        else:
            print("Creating locker file at {}".format(os.path.abspath(self.filename)))
            self.set_passphrase()
            self.write_file()

    def write_file(self) -> None:
        """ Write the encrypted locker to the filesystem. """
        locker_encoded = json.dumps(self.decrypted_locker_decoded).encode()
        encrypted_locker = self.password_encrypt(locker_encoded, self.passphrase, 10)

        with open(self.filename, 'wb') as f:
            f.write(encrypted_locker)
            print('Wrote {} encrypted {} to {}'.format(len(encrypted_locker), type(encrypted_locker), self.filename))

    def main_menu(self) -> None:
        """ Display the main menu and prompt the user for input. """
        print("Current locker file '{}'".format(os.path.abspath(self.filename)))
        self.cmd_input = input("[a]dd entry, [s]how-all, [q]uit or search: ").lower().strip()

    def add_entry(self) -> None:
        """ Create the json locker entry """
        entry = {}
        locker_name = input('Locker Name: ')
        email = input('Email Address: ')
        password = input('Password: ')

        extra_entry = {}
        extra = True
        extra_count = 1

        while extra != '':
            key = 'Extra {}: '.format(extra_count)
            extra = input(key)
            extra_entry[key] = extra
            extra_count += 1

        # Dict update after final, empty entry has been added, so remove.
        del extra_entry[key]

        entry = {
            locker_name : {
                "email" : email,
                "password" : password,
                "extra" : extra_entry
            }
        }

        if bool(self.decrypted_locker_decoded) is False:
            self.decrypted_locker_decoded = entry
        else:
            self.decrypted_locker_decoded.update(entry)

    def show_all(self) -> None:
        """ Show all the locker entries. """
        if not len(self.decrypted_locker_decoded):
            print('No items in locker')
        else:
            for locker_key, locker in self.decrypted_locker_decoded.items():
                print("Locker key: '{}'".format(locker_key))

        return None

    def search(self) -> None:
        """ Search the locker for the input string. When a match is found, show all fields. """
        match = False
        for locker_key, locker in self.decrypted_locker_decoded.items():
            if self.cmd_input in locker_key:
                match = True

            if match:
                print("Matched on '{}'".format(locker_key))
                for k, v in locker.items():
                    print("\t {}: {}".format(k, v))

            match = False

        return None
    
    def act_on_command(self) -> None:
        """ This controls what input we action off of. """
        while self.cmd_input != 'q':
            if self.cmd_input == 'a':
                self.add_entry()
                self.write_file()
            elif self.cmd_input == 's':
                self.show_all()
            else:
                self.search()

            self.main_menu()

        return None

    def run(self) -> None:
        """ The main run loop. """
        try:
            self.load_or_create_locker()
            self.main_menu()
            self.act_on_command()
        except:
            print("\n{} failed, shutting down!".format(type(self).__name__))

        return None

# Main
locker = PyLocker()
locker.run()
