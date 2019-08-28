import argparse
import json
import os
import re
import stdiomask
import secrets

from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()

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

     
def get_lockerfile():
    filename = input("Enter locker file path: ")
    if os.path.exists(filename):
        print("File exists, try again")
        get_lockerfile()

    return filename

def get_passphrase():
    passphrase = stdiomask.getpass(prompt='Enter passphrase: ', mask='*')

    return passphrase

def main_menu(filename):
    print("[!] Current locker file {}".format(filename))
    cmd_input = input("[a]dd entry, [s]ave & exit or search:")

    return cmd_input

def main():
    cmd_parser = argparse.ArgumentParser(description='Decrypt locker')
    cmd_parser.add_argument('-f', '--file', help='File location to descrypt', required=False)
    args = vars(cmd_parser.parse_args())
    filename = args['file']
    locker = {}
    
    # Check if file exists and is not empty
    if os.path.exists(filename) and os.stat(filename).st_size != 0:
        print("Locker file found, or file is empty")
        passphrase = get_passphrase()
        #key = _derive_key(passphrase, 8, 10)
        # Read in contents of encrypted file
        with open(filename) as f:
            encrypted_bytes = f.read().encode()

        print("Encrypted bytes {}".format(encrypted_bytes))

        # Decrypt
        decrypted_locker = password_decrypt(encrypted_bytes, passphrase)
        if decrypted_locker is False:
            print("[!] Invalid token, exiting.")
            return False
        
        print("Decrypted locker {}".format(decrypted_locker))
    else:
        print("Unable to locate locker file")
        filename = get_lockerfile()
        passphrase = get_passphrase()

    cmd_input = main_menu(filename).lower().strip()

    if cmd_input == 'a':
        entry_dict = {}
        meta = input("Meta:  ")
        email = input("Email address: ")
        password = input("Password: ")

        extra_dict = {}
        extra = True
        extra_count = 1
        while extra != '':
            key = "Extra {}".format(extra_count)
            extra = input(key)
            extra_dict[key] = extra
            extra_count += 1

        # Dict updates after final empty entry has been added, remove. 
        del extra_dict[key]
        print(extra_dict)

        entry_dict = {
            'meta' : meta,
            'email' : email,
            'password' : password,
            'extra': extra_dict
        }

        print(entry_dict)

        # Encrypt
        print(passphrase)
        print(type(passphrase))
        locker_bytes = json.dumps(entry_dict).encode()
        encrypted_locker = password_encrypt(locker_bytes, passphrase, 10)
        #print(locker_str)
        #print(type(locker_str))
        print(encrypted_locker)
        # Write the encrypted bytes to the output file
        with open(filename, 'wb') as f:
            f.write(encrypted_locker)
            print("[!] Wrote {} encrypted {} to {}".format(len(encrypted_locker), type(encrypted_locker), filename))
            
        with open(filename + '.json-debug', 'w', encoding='utf-8') as f:
            json.dump(entry_dict, f, ensure_ascii=False, indent=4)

    elif cmd_input == 's':
        pass
    else:
        decrypted_locker_dict = json.loads(decrypted_locker.decode("utf-8"))
        #print(type(decrypted_locker))
        #print(decrypted_locker_dict)
        match = False
        for key, value in decrypted_locker_dict.items():
            #print("key: %s value: %s" % (key, value))
            if key in 'meta': # regex not needed, I think. 
                if cmd_input in value.lower().strip():
                    print("found match")
                    match = True
            if match:
                print("{}: {}".format(key, value))

#
# Main
#
main()

