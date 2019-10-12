
"""
Common interface for all modes and key lengths
"""
function decrypt(ciphertext::AESCipherText, cipher::AES)
	if ciphertext.mode !== cipher.mode
		error("Mismatching mode and cipher")
	end
	if ciphertext.keylength !== get_key_length(cipher)
		error("Mismatching keylength")
	end
	if cipher.mode == CBC

	elseif cipher.mode == ECB
		raw = AESCBC_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
	end
end
