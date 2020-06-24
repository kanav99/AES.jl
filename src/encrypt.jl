"""
Common interface for all modes and key lengths
"""
function encrypt end

encrypt(plain, cipher::AESCipher{CBC,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt(Array{UInt8}(plain), cipher, iv)
encrypt(plain, cipher::AESCipher{CTR,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt(Array{UInt8}(plain), cipher, iv)
encrypt(plain, cipher::AESCipher) = encrypt(Array{UInt8}(plain), cipher)

encrypt(plaintext::AbstractArray{UInt8}, cipher::AESCipher{CBC,T,U}, iv) where {T,U} = AESCipherText(AESCBC(plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
encrypt(plaintext::AbstractArray{UInt8}, cipher::AESCipher{CTR,T,U}, iv) where {T,U} = AESCipherText(AESCTR(plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
encrypt(plaintext::AbstractArray{UInt8}, cipher::AESCipher{ECB,T,U}) where {T,U} = AESCipherText(AESECB(plaintext, cipher.key, cipher.cache), nothing, get_key_length(cipher), get_mode(cipher), typeof(plaintext))

encrypt!(ciphertext, plaintext, cipher::AESCipher{CBC,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt!(ciphertext, Array{UInt8}(plaintext), cipher, iv)
encrypt!(ciphertext, plaintext, cipher::AESCipher{CTR,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt!(ciphertext, Array{UInt8}(plaintext), cipher, iv)
encrypt!(ciphertext, plaintext, cipher::AESCipher) = encrypt!(ciphertext, Array{UInt8}(plaintext), cipher)
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::AESCipher{CBC,T,U}, iv) where {T,U} = AESCipherText(AESCBC!(ciphertext, plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::AESCipher{CTR,T,U}, iv) where {T,U} = AESCipherText(AESCTR!(ciphertext, plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::AESCipher{ECB,T,U}) where {T,U} = AESCipherText(AESECB!(ciphertext, plaintext, cipher.key, cipher.cache), nothing, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
