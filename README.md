# libzotp

#### This library provides the following:
- Interface for generating OTP.
- Interface to decrypt [andOTP](https://github.com/andOTP/andOTP) encrypted JSON file.
- Interface to encrypt JSON file (andOTP-compatible) (WIP).

# Pre-requisits
- Requires gcc, openssl installed.


## Installation
(This will install library in ````/usr/local/lib directory````. Please make sure env. variable ````$LD_LIBRARY_PATH```` recognizes this path)
````
$ make && sudo make install
````


# Licence
[MIT](https://gitlab.com/GRijul/libzotp/-/blob/master/LICENCE)