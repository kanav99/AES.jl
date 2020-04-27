
"""
Common interface for all modes and key lengths
"""
function decrypt(ciphertext::AESCipherText, cipher::AES; remove_pad=true)
	if ciphertext.mode !== get_mode(cipher)
		error("Mismatching mode and cipher")
	end
	if ciphertext.keylength !== get_key_length(cipher)
		error("Mismatching keylength")
	end
	if iscbc(cipher)
		raw = AESCBC_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache, remove_pad)
	elseif isctr(cipher)
		raw = AESCTR_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
	elseif isecb(cipher)
		raw = AESECB_D(ciphertext.data, cipher.key, cipher.cache)
	end
	return (ciphertext.original_type)(raw)
end

function decrypt!(plaintext, ciphertext::AESCipherText, cipher::AES; remove_pad=true)
	if ciphertext.mode !== get_mode(cipher)
		error("Mismatching mode and cipher")
	end
	if ciphertext.keylength !== get_key_length(cipher)
		error("Mismatching keylength")
	end
	if iscbc(cipher)
		AESCBC_D!(plaintext, ciphertext.data, ciphertext.iv, cipher.key, cipher.cache, remove_pad)
	elseif isctr(cipher)
		AESCTR_D!(plaintext, ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
	elseif isecb(cipher)
		AESECB_D!(plaintext, ciphertext.data, cipher.key, cipher.cache)
	end
	return (ciphertext.original_type)(plaintext)
end

