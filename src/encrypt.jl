
"""
Common interface for all modes and key lengths
"""
function encrypt(plaintext::Union{String,Array{UInt8}}, cipher::AES)
	if cipher.mode == CBC
		return AESCBC(plaintext, cipher.iv, cipher.key, cipher.cache)
	elseif cipher.mode == ECB
		return AESECB(plaintext, cipher.key, cipher.cache)
	end
end
