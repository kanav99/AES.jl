
"""
Common interface for all modes and key lengths
"""
function decrypt(ciphertext::AESCipherText, cipher::AES;remove_pad=true)
	if ciphertext.mode !== cipher.mode
		error("Mismatching mode and cipher")
	end
	if ciphertext.keylength !== get_key_length(cipher)
		error("Mismatching keylength")
	end
	if cipher.mode == CBC
		raw = AESCBC_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache, remove_pad)
	elseif cipher.mode == ECB
		raw = AESECB_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
	elseif cipher.mode == CTR
		raw = AESCTR_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
	end
end
