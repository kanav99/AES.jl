"""
Common interface for all modes and key lengths
"""
function decrypt end

decrypt(ciphertext::CT{IV,CBC}, cipher::Cipher{CBC,ct,kt}; remove_pad=true) where {IV,ct,kt} = AESCBC_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache; remove_pad=remove_pad)
decrypt(ciphertext::CT{IV,CTR}, cipher::Cipher{CTR,ct,kt}) where {IV,ct,kt} = AESCTR_D(ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
decrypt(ciphertext::CT{IV,ECB}, cipher::Cipher{ECB,ct,kt}) where {IV,ct,kt} = AESECB_D(ciphertext.data, cipher.key, cipher.cache)

decrypt!(plaintext, ciphertext::CT{IV,CBC}, cipher::Cipher{CBC,ct,kt}; remove_pad=true) where {IV,ct,kt} = AESCBC_D!(plaintext, ciphertext.data, ciphertext.iv, cipher.key, cipher.cache; remove_pad=remove_pad)
decrypt!(plaintext, ciphertext::CT{IV,CTR}, cipher::Cipher{CTR,ct,kt}) where {IV,ct,kt} = AESCTR_D!(plaintext, ciphertext.data, ciphertext.iv, cipher.key, cipher.cache)
decrypt!(plaintext, ciphertext::CT{IV,ECB}, cipher::Cipher{ECB,ct,kt}) where {IV,ct,kt} = AESECB_D!(plaintext, ciphertext.data, cipher.key, cipher.cache)
