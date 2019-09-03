import argparse
import json
import os
import secrets
import signal
import stdiomask
import sys

from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()

def signal_handler(sig, frame):
    print("[!] Signal caught, exiting.")
    sys.exit(0)

def _derive_key(password, salt, iterations):
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message, password, iterations):
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token, password):
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    try:
        plaintext = Fernet(key).decrypt(token)
        return plaintext
    except:
        return False

def get_passphrase():
    passphrase = stdiomask.getpass(prompt='Enter passphrase: ', mask='*')

    return passphrase
    
def set_passphrase():
    passphrase = stdiomask.getpass(prompt='Enter passphrase: ', mask='*')
    confirmed_passphrase = stdiomask.getpass(prompt='Confirm passphrase: ', mask='*')    

    if passphrase != confirmed_passphrase:
        print("[!] Passphrases do not match")
        get_passphrase()
    
    return passphrase

def main_menu(filename):
    print("Current locker file '{}'".format(os.path.abspath(filename)))
    cmd_input = input("[a]dd entry, [s]how-all, [q]uit or search: ")
    cmd_input = cmd_input.lower().strip()

    return cmd_input

def add_entry(decrypted_locker_dict, passphrase, filename):
    entry_dict = {}
    meta = input("Locker Name:  ")
    email = input("Email Address: ")
    password = input("Password: ")

    extra_dict = {}
    extra = True
    extra_count = 1
    while extra != '':
        key = "Extra {}: ".format(extra_count)
        extra = input(key)
        extra_dict[key] = extra
        extra_count += 1
        
    # Dict updates after final empty entry has been added, remove. 
    del extra_dict[key]
    print("Extra dict: {}".format(extra_dict))

    entry_dict = {
        meta : {
            "email" : email,
            "password" : password,
            "extra": extra_dict
        }
    }

    if bool(decrypted_locker_dict) is False:
        decrypted_locker_dict = entry_dict
    else:
        decrypted_locker_dict.update(entry_dict)
        decrypted_locker_dict = dict(decrypted_locker_dict, **entry_dict)

    return decrypted_locker_dict

def write_file(decrypted_locker_dict, passphrase, filename):
    # Encrypt
    locker_bytes = json.dumps(decrypted_locker_dict).encode()
    encrypted_locker = password_encrypt(locker_bytes, passphrase, 10)

    # Write the encrypted bytes to the output file
    with open(filename, 'wb') as f:
        f.write(encrypted_locker)
        print("Wrote {} encrypted {} to {}".format(len(encrypted_locker), type(encrypted_locker), filename))

    json_string = decrypted_locker_dict
    print("json string: {} with type {}".format(json_string, type(json_string)))
    with open(filename + '.json-debug', 'w', encoding='utf-8') as f:
        json.dump(json_string, f, ensure_ascii=False, indent=4)

        
def main():
    cmd_parser = argparse.ArgumentParser(description='Decrypt locker')
    cmd_parser.add_argument('-f', '--file', help='File location to descrypt', required=True)
    args = vars(cmd_parser.parse_args())
    filename = args['file']
    locker = {}
    decrypted_locker_dict = {}
    
    # Check if file exists and is not empty
    if os.path.exists(filename) and os.stat(filename).st_size != 0:
        print("Locker file found")
        passphrase = get_passphrase()

        # Read in contents of encrypted file
        with open(filename) as f:
            encrypted_bytes = f.read().encode()

        # Decrypt
        decrypted_locker = password_decrypt(encrypted_bytes, passphrase)
        if decrypted_locker is False:
            print("Invalid token, exiting.")
            sys.exit()

        decrypted_locker_dict = json.loads(decrypted_locker.decode("utf-8"))
    else:
        #print("Unable to locate locker file")
        #filename = get_lockerfile()
        print("Creating lock file at {}".format(os.path.abspath(filename)))
        passphrase = set_passphrase()

    cmd_input = False
    while cmd_input != 'q':
        cmd_input = main_menu(filename)

        if cmd_input == 'a':
            decrypted_locker_dict = add_entry(decrypted_locker_dict, passphrase, filename)

            # Now write to file, kind of like auto-save.
            write_file(decrypted_locker_dict, passphrase, filename)
        elif cmd_input == 'e':
            

        elif cmd_input == 's':
            if len(decrypted_locker_dict) == 0:
                print("No items in locker")
            else:
                for meta_key, meta_dict in decrypted_locker_dict.items():
                    print("Meta key: {}".format(meta_key))

        elif cmd_input == 'q':
            print("Shutting down, good-bye!")
            sys.exit()

        else:
            match = False
            for meta_key, meta_dict in decrypted_locker_dict.items():
                if cmd_input in meta_key:
                    match = True

                if match:
                    print("Matched on '{}'".format(meta_key))
                    for k,v in meta_dict.items():
                        print("\t {}: {}".format(k, v))

                match = False

#
# Main
#
signal.signal(signal.SIGINT, signal_handler)
main()

