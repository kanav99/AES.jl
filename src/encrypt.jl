"""
Common interface for all modes and key lengths
"""
function encrypt(plaintext::Union{String,Array{UInt8}}, cipher::AESCipher;
				 iv=needs_iv(cipher) ? rand(UInt8, 16) : nothing)
	if iscbc(cipher)
		ciphertext = AESCBC(plaintext, iv, cipher.key, cipher.cache)
	elseif isctr(cipher)
		ciphertext = AESCTR(plaintext, iv, cipher.key, cipher.cache)
	elseif isecb(cipher)
		ciphertext = AESECB(plaintext, cipher.key, cipher.cache)
	end
	return AESCipherText(ciphertext, iv, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
end

function encrypt!(ciphertext, plaintext::Union{String,Array{UInt8}}, cipher::AESCipher;
				 iv=needs_iv(cipher) ? rand(UInt8, 16) : nothing)
	if iscbc(cipher)
		AESCBC!(ciphertext, plaintext, iv, cipher.key, cipher.cache)
	elseif isctr(cipher)
		AESCTR!(ciphertext, plaintext, iv, cipher.key, cipher.cache)
	elseif isecb(cipher)
		AESECB!(ciphertext, plaintext, cipher.key, cipher.cache)
	end
	return AESCipherText(ciphertext, iv, get_key_length(cipher), get_mode(cipher), typeof(plaintext))
end
