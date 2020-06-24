"""
Common interface for all modes and key lengths
"""
function encrypt end

encrypt(plain, cipher::Cipher{CBC,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt(transcode(UInt8, plain), cipher, iv)
encrypt(plain, cipher::Cipher{CTR,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt(transcode(UInt8, plain), cipher, iv)
encrypt(plain, cipher::Cipher) = encrypt(transcode(UInt8, plain), cipher)

encrypt(plaintext::AbstractArray{UInt8}, cipher::Cipher{CBC,T,U}, iv) where {T,U} = CipherText(AESCBC(plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CBC)
encrypt(plaintext::AbstractArray{UInt8}, cipher::Cipher{CTR,T,U}, iv) where {T,U} = CipherText(AESCTR(plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CTR)
encrypt(plaintext::AbstractArray{UInt8}, cipher::Cipher{ECB,T,U}) where {T,U} = CipherText(AESECB(plaintext, cipher.key, cipher.cache), nothing, get_key_length(cipher), ECB)

encrypt!(ciphertext, plaintext, cipher::Cipher{CBC,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt!(ciphertext, transcode(UInt8, plaintext), cipher, iv)
encrypt!(ciphertext, plaintext, cipher::Cipher{CTR,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt!(ciphertext, transcode(UInt8, plaintext), cipher, iv)
encrypt!(ciphertext, plaintext, cipher::Cipher) = encrypt!(ciphertext, transcode(UInt8, plaintext), cipher)

encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::Cipher{CBC,T,U}, iv) where {T,U} = CipherText(AESCBC!(ciphertext, plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CBC)
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::Cipher{CTR,T,U}, iv) where {T,U} = CipherText(AESCTR!(ciphertext, plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CTR)
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::Cipher{ECB,T,U}) where {T,U} = CipherText(AESECB!(ciphertext, plaintext, cipher.key, cipher.cache), nothing, get_key_length(cipher), ECB)
