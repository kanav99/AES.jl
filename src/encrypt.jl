
"""
Common interface for all modes and key lengths
"""
function encrypt(plaintext::Union{String,Array{UInt8}}, cipher::AES)
	if cipher.mode == CBC
		raw = AESCBC(plaintext, cipher.iv, cipher.key, cipher.cache)
		return AESCipherText(raw, cipher.iv, get_key_length(cipher), CBC, typeof(plaintext))
	elseif cipher.mode == ECB
		raw = AESECB(plaintext, cipher.key, cipher.cache)
		return AESCipherText(raw, nothing, get_key_length(cipher), ECB, typeof(plaintext))
	end
end
