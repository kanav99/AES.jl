
function AESCBC(plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(plaintext)
	pad = 16 - (len % 16)
	ciphertext = similar(Array{UInt8, 1}, pad + len)
	AESCBC!(ciphertext, plaintext, iv, key, cache)
end

function AESCBC!(ciphertext, plaintext, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache)
	len = length(plaintext)
	pad = 16 - (len % 16)
	for i in 1:len
		ciphertext[i] = UInt8(plaintext[i])
	end
	for i in 1:pad
		ciphertext[len+i] = pad
	end
	iters = Int((len + pad) / 16)
	ciphertextblock = AESBlock(ciphertext)
	prevblock = AESBlock(ciphertext)
	# iteration 1 start
	ciphertextblock .⊻= iv
	AESEncryptBlock!(ciphertextblock, ciphertextblock, key, cache)
	increment!(ciphertextblock)
	# iteration 1 end
	for i in 2:iters
		@. ciphertextblock ⊻= prevblock
		AESEncryptBlock!(ciphertextblock, ciphertextblock, key, cache)
		increment!(ciphertextblock)
		increment!(prevblock)
	end
	ciphertext
end

function AESCBC_D(ciphertext::Array{UInt8, 1}, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache; remove_pad=true)
	len = length(ciphertext)
	iters = Int(len / 16)
	plaintext = similar(Array{UInt8, 1}, len)
	AESCBC_D!(plaintext, ciphertext, iv, key, cache; remove_pad=remove_pad)
end

function AESCBC_D!(plaintext, ciphertext::Array{UInt8, 1}, iv::Array{UInt8, 1}, key::AbstractAESKey, cache::AbstractAESCache; remove_pad=true)
	len = length(ciphertext)
	iters = Int(len / 16)
	plaintextblock = AESBlock(plaintext)
	ciphertextblock = AESBlock(ciphertext)
	prevblock = AESBlock(ciphertext)
	# iteration 1 start
	AESDecryptBlock!(plaintextblock, ciphertextblock, key, cache)
	plaintextblock .⊻= iv
	increment!(plaintextblock)
	increment!(ciphertextblock)
	# iteration 1 end
	for i in 2:iters
		AESDecryptBlock!(plaintextblock, ciphertextblock, key, cache)
		plaintextblock .⊻= prevblock
		increment!(plaintextblock)
		increment!(ciphertextblock)
		increment!(prevblock)
	end
	if remove_pad
		pad = plaintext[end]
		@view(plaintext[1:len-pad])
	else
		plaintext
	end
end

