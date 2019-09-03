PyLocker
======

A python based vault that runs interactively, allowing you to decrypt/encrypt a 'locker'.

The locker entries are as follows:

    {
        "ben sgro gmail personal": {
            "email": "ben.sgro@gmail.com",
            "password": "somepassw0rd",
            "extra": {}
        }
    }

The key is unique, and stores a dictionary of data including email, password and an extra dictionary, that can contain any arbitrary number of entires (think 2FA back-up codes, Q/A challenges, etc).
