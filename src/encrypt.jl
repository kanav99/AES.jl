"""
Common interface for all modes and key lengths
"""
function encrypt end

encrypt(plain, cipher::Cipher{CBC,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt(Array{UInt8}(plain), cipher, iv)
encrypt(plain, cipher::Cipher{CTR,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt(Array{UInt8}(plain), cipher, iv)
encrypt(plain, cipher::Cipher) = encrypt(Array{UInt8}(plain), cipher)

encrypt(plaintext::AbstractArray{UInt8}, cipher::Cipher{CBC,T,U}, iv) where {T,U} = CipherText(AESCBC(plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CBC, typeof(plaintext))
encrypt(plaintext::AbstractArray{UInt8}, cipher::Cipher{CTR,T,U}, iv) where {T,U} = CipherText(AESCTR(plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CTR, typeof(plaintext))
encrypt(plaintext::AbstractArray{UInt8}, cipher::Cipher{ECB,T,U}) where {T,U} = CipherText(AESECB(plaintext, cipher.key, cipher.cache), nothing, get_key_length(cipher), ECB, typeof(plaintext))

encrypt!(ciphertext, plaintext, cipher::Cipher{CBC,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt!(ciphertext, Array{UInt8}(plaintext), cipher, iv)
encrypt!(ciphertext, plaintext, cipher::Cipher{CTR,T,U}; iv=rand(UInt8, 16)) where {T,U} = encrypt!(ciphertext, Array{UInt8}(plaintext), cipher, iv)
encrypt!(ciphertext, plaintext, cipher::Cipher) = encrypt!(ciphertext, Array{UInt8}(plaintext), cipher)

encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::Cipher{CBC,T,U}, iv) where {T,U} = CipherText(AESCBC!(ciphertext, plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CBC, typeof(plaintext))
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::Cipher{CTR,T,U}, iv) where {T,U} = CipherText(AESCTR!(ciphertext, plaintext, iv, cipher.key, cipher.cache), iv, get_key_length(cipher), CTR, typeof(plaintext))
encrypt!(ciphertext, plaintext::AbstractArray{UInt8}, cipher::Cipher{ECB,T,U}) where {T,U} = CipherText(AESECB!(ciphertext, plaintext, cipher.key, cipher.cache), nothing, get_key_length(cipher), ECB, typeof(plaintext))
