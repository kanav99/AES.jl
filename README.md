# AES.jl

[![Build Status](https://travis-ci.org/kanav99/AES.jl.svg?branch=master)](https://travis-ci.org/kanav99/AES.jl)

AES On-the-Fly mode in Julia

## API
```julia
using AES

# make a new key
k = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
key = AES128Key(k)

# make a cipher object
cipher = AESCipher(;key_length=128, mode=AES.CBC, key=key)

# encrypt!
plaintext = "The quick brown fox jumps over the lazy dog."
ct = encrypt(plaintext, cipher)
pt = decrypt(ct, cipher)
@assert pt === plaintext

# you can set custom initialization vector
iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
ct = encrypt(plaintext, cipher; iv=iv)
pt = decrypt(ct, cipher)

@assert pt == transcode(UInt8, plaintext)
# or, if it's known that the original plaintext was valid UTF-8
@assert String(pt) == plaintext
```
