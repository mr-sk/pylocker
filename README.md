PyLocker
======

A python based vault that runs interactively, allowing you to decrypt/encrypt a 'locker'.

The locker entries are as follows:

    {
        "mr sk gmail personal": {
            "email": "some.email@gmail.com",
            "password": "somepassw0rd",
            "extra": {}
        }
    }

The key is unique, and stores a dictionary of data including email, password and an extra dictionary, that can contain any arbitrary number of entries (think 2FA back-up codes, Q/A challenges, etc).

Usage
-----

A typical session to retrieve a password would look like this:

    python3 pylocker.py -f pass.txt
    Locker file found
    Enter passphrase: ********
    Current locker file '/Users/bsgro/Research/pylocker/pass.txt'
    [a]dd entry, [s]how-all, [q]uit or search: sk
    Meta key: mr sk gmail personal
    Current locker file '/Users/bsgro/Research/pylocker/pass.txt'
    [a]dd entry, [s]how-all, [q]uit or search: gmail person
    Matched on 'mr sk gmail personal'
	     email: some.email@gmail.com
	     password: somepassw0rd
	     extra: {}
    Current locker file '/Users/bsgro/Research/pylocker/pass.txt'
    [a]dd entry, [s]how-all, [q]uit or search: q
    Shutting down, good-bye!


Installation
------------

Create a virtual environment (if you want). 

    pip install -r requirements.txt
    python3 pylocker.py -f path/to/locker.txt
    
