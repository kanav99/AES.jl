

function AESCTR(plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
    len = length(plaintext)
    pad = 16 - (len % 16)
    result = similar(Array{UInt8, 1}, len)
    for i in 1:len
        result[i] = UInt8(plaintext[i])
    end
    iters = Int((len + pad) / 16)
    copy_iv = copy(iv)
    copy_iv2 = copy(iv)
    for i in 1:iters
        start = 16(i-1)+1
        ending = 16i
        copy_iv2[end] = iv[end] + i - 1
        AESEncryptBlock!(copy_iv, copy_iv2, key.key, cache)
        if i == iters
            for j in start:len
                result[j] = result[j] ⊻ copy_iv[j % 16]
            end
            break
        else
            view_res = @view(result[start:ending])
            @. view_res = view_res ⊻ copy_iv
        end
    end
    result
end

AESCTR_D(ciphertext::Array{UInt8, 1}, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache) = AESCTR(ciphertext, iv, key, cache)