

function AESECB(plaintext, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(plaintext)
	pad = 16 - (len % 16)
	result = similar(Array{UInt8, 1}, pad + len)
	for i in 1:len
		result[i] = UInt8(plaintext[i])
	end
	for i in 1:pad
		result[len+i] = pad
	end
	iters = Int((len + pad) / 16)
	for i in 1:iters
		start = 16(i-1)+1
		ending = 16i
		view_res = @view(result[start:ending])
		AESEncryptBlock!(view_res, view_res, key, cache)
	end
	result
end

function AESECB_D(ciphertext::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(ciphertext)
	iters = Int(len / 16)
	result = similar(Array{UInt8, 1}, len)
	for i in 1:iters
		start = 16(i-1)+1
		ending = 16i
		ct_view = @view(ciphertext[start:ending])
		res_view = @view(result[start:ending])
		AESDecryptBlock!(res_view, ct_view, key.key, cache)
	end
	pad = result[end]
	result[1:len-pad]
end

