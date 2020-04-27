

function AESCTR(plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
    len = length(plaintext)
    pad = 16 - (len % 16)
    result = similar(Array{UInt8, 1}, len)
    iters = Int((len + pad) / 16)
    counter = cache.modecache
    counter .= iv
    for i in 1:(iters-1)
        start = 16(i-1)+1
        ending = 16i
        resultview = @view(result[start:ending])
        AESEncryptBlock!(resultview, counter, key, cache)
        @. resultview ⊻= @view(plaintext[start:ending])
        increment!(counter)
    end
    # for the last iteration, we dont need counter no more
    # we can use the inplace property of AES
    AESEncryptBlock!(counter, counter, key, cache)
    start = 16(iters-1)+1
    @. @view(result[start:len]) = @view(plaintext[start:len]) ⊻ @view(counter[start:len])
    result
end

AESCTR_D(ciphertext::Array{UInt8, 1}, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache) = AESCTR(ciphertext, iv, key, cache)
