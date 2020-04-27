
function AESECB(plaintext, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(plaintext)
	pad = 16 - (len % 16)
	ciphertext = similar(Array{UInt8, 1}, pad + len)
	AESECB!(ciphertext, plaintext, key, cache)
end

function AESECB!(ciphertext, plaintext, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(plaintext)
	pad = 16 - (len % 16)
	for i in 1:len
		ciphertext[i] = UInt8(plaintext[i])
	end
	for i in 1:pad
		ciphertext[len+i] = pad
	end
	iters = Int((len + pad) / 16)
	for i in 1:iters
		start = 16(i-1)+1
		ending = 16i
		view_res = @view(ciphertext[start:ending])
		AESEncryptBlock!(view_res, view_res, key, cache)
	end
	ciphertext
end

function AESECB_D(ciphertext::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(ciphertext)
	iters = Int(len / 16)
	plaintext = similar(Array{UInt8, 1}, len)
	AESECB_D!(plaintext, ciphertext, key, cache)
end

function AESECB_D!(plaintext, ciphertext::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(ciphertext)
	iters = Int(len / 16)
	for i in 1:iters
		start = 16(i-1)+1
		ending = 16i
		ct_view = @view(ciphertext[start:ending])
		res_view = @view(plaintext[start:ending])
		AESDecryptBlock!(res_view, ct_view, key, cache)
	end
	pad = plaintext[end]
	@view(plaintext[1:len-pad])
end
