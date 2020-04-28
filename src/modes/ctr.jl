
function AESCTR(plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
    len = length(plaintext)
    ciphertext = similar(Array{UInt8, 1}, len)
    AESCTR!(ciphertext, plaintext, iv, key, cache)
end

function AESCTR!(ciphertext, plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
    len = length(plaintext)
    pad = 16 - (len % 16)
    iters = Int((len + pad) / 16)
    counter = cache.modecache
    counter .= iv
    ciphertextblock = AESBlock(ciphertext)
    plaintextblock = AESBlock(plaintext)
    for i in 1:(iters-1)
        AESEncryptBlock!(ciphertextblock, counter, key, cache)
        @. ciphertextblock ⊻= plaintextblock
        increment!(counter)
        increment!(ciphertextblock)
        increment!(plaintextblock)
    end
    # for the last iteration, we dont need counter no more
    # we can use the inplace property of AES
    AESEncryptBlock!(counter, counter, key, cache)
    offset = 16(iters-1)
    for i in 1:(16-pad)
        ciphertext[offset+i] = UInt8(plaintext[offset+i]) ⊻ counter[i]
    end
    ciphertext
end

# Encryption is same as decryption in CTR mode for a give Key and IV
AESCTR_D = AESCTR
AESCTR_D! = AESCTR!
