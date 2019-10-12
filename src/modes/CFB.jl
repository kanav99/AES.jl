

function AESCFB(plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
    len = length(plaintext)
    result = similar(Array{UInt8, 1}, len)
    for i in 1:len
        result[i] = UInt8(plaintext[i])
    end
    iters = Int(ceil(len / 16)) + 1
    temp_arr = copy(iv)
    for i in 1:iters
        start = 16(i-1)+1
        ending = 16i
        if i == 1
            AESEncryptBlock!(temp_arr, iv, key, cache)
        else
            AESEncryptBlock!(temp_arr, @view(result[start-16:ending-16]), key, cache)
        end
        if i == iters
            for j in start:len
                result[j] = result[j] ⊻ temp_arr[j % 16]
            end
        else
            view_res = @view(result[start:ending])
            @. view_res = view_res ⊻ temp_arr
        end
    end
    result
end
