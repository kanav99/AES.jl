function AES128ECB_D(ciphertext::Array{UInt8, 1}, key::AES128Key)
	len = length(ciphertext)
	iters = Int(len / 16)
	result = similar(Array{UInt8, 1}, len)
	cache = AES128Cache()
	for i in 1:iters
		start = 16(i-1)+1
		ending = 16i
		ct_res = @view(ciphertext[start:ending])
		view_res = @view(result[start:ending])
		AESDecryptBlock!(view_res, ct_res, key.key, cache)
	end
	pad = result[end]
	result[1:len-pad]
end

