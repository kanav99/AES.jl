
"""
Common interface for all modes and key lengths
"""
function encrypt(plaintext::Union{String,Array{UInt8}}, cipher::AES;
				 iv=needs_iv(cipher.mode) ? rand(UInt8, 16) : nothing)
	if cipher.mode == CBC
		raw = AESCBC(plaintext, iv, cipher.key, cipher.cache)
		return AESCipherText(raw, iv, get_key_length(cipher), CBC, typeof(plaintext))
	elseif cipher.mode == ECB
		raw = AESECB(plaintext, cipher.key, cipher.cache)
		return AESCipherText(raw, nothing, get_key_length(cipher), ECB, typeof(plaintext))
	end
end
