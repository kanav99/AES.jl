

function AESCTR(plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
    len = length(plaintext)
    result = similar(Array{UInt8, 1}, len)
    for i in 1:len
        result[i] = UInt8(plaintext[i])
    end
    iters = Int(ceil(len / 16)) + 1
    copy_iv = copy(iv)
    copy_iv2 = copy(iv)
    for i in 1:iters
        start = 16(i-1)+1
        ending = 16i
        if i != 1
            for j in 1:len
                if copy_iv2[end-j+1] == 0xff
                    copy_iv2[end-j+1] = 0x00
                else
                    copy_iv2[end-j+1] = copy_iv2[end-j+1] + 1
                    break
                end
            end
        end
        AESEncryptBlock!(copy_iv, copy_iv2, key, cache)
        if i == iters
            for j in start:len
                result[j] = result[j] ⊻ copy_iv[j % 16]
            end
        else
            view_res = @view(result[start:ending])
            @. view_res = view_res ⊻ copy_iv
        end
    end
    result
end

AESCTR_D(ciphertext::Array{UInt8, 1}, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache) = AESCTR(ciphertext, iv, key, cache)