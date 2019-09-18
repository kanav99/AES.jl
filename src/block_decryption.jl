function AESDecryptBlock!(result::Union{Array{UInt8, 1}, SubArray{UInt8}}, block::Union{Array{UInt8, 1}, SubArray{UInt8}}, key::Array{UInt8})
	cache = AES128Cache()
	AESDecryptBlock!(result, block, key, cache)
end

function AESDecryptBlock!(result::Union{Array{UInt8, 1}, SubArray{UInt8}}, block::Union{Array{UInt8, 1}, SubArray{UInt8}}, key::Array{UInt8}, cache::AES128Cache)
	current = result
	copyto!(current, block)
	K = cache.K
	tmp = cache.tmp

	for i in 1:4
		for j in 1:4
			K[i][j] = key[4i+j-4]
		end
	end
	# Generate last round key
	for i in 2:11
		copyto!(tmp, K[4])
		for j in 1:4
			tmp[j] = SBOX[tmp[j]+1]
		end
		tmp1 = tmp[1]
		tmp[1] = tmp[2]
		tmp[2] = tmp[3]
		tmp[3] = tmp[4]
		tmp[4] = tmp1
		K[1] .= K[1] .⊻ tmp
		K[1][1] = K[1][1] ⊻ RCON[i - 1]
		K[2] .= K[2] .⊻ K[1]
		K[3] .= K[3] .⊻ K[2]
		K[4] .= K[4] .⊻ K[3]
	end
	# Start Rounds
	for i in 1:11
		# AddRoundKey
		for j in 1:4
			for k in 1:4
				current[4j+k-4] = current[4j+k-4] ⊻ K[j][k]
			end
		end
		if i < 11
			# GenNextRoundKey
			K[4] .= K[4] .⊻ K[3]
			K[3] .= K[3] .⊻ K[2]
			K[2] .= K[2] .⊻ K[1]
			copyto!(tmp, K[4])
			for j in 1:4
				tmp[j] = SBOX[tmp[j]+1]
			end
			tmp1 = tmp[1]
			tmp[1] = tmp[2]
			tmp[2] = tmp[3]
			tmp[3] = tmp[4]
			tmp[4] = tmp1
			K[1] .= K[1] .⊻ tmp
			K[1][1] = K[1][1] ⊻ RCON[11 - i]
			# InvMixColumns
			if i != 1
				for j in 1:4
					tmp[1] = aes_mul(current[4j-3], 0xE) ⊻ aes_mul(current[4j-2], 0xB) ⊻ aes_mul(current[4j-1], 0xD) ⊻ aes_mul(current[4j], 0x9)
					tmp[2] = aes_mul(current[4j-3], 0x9) ⊻ aes_mul(current[4j-2], 0xE) ⊻ aes_mul(current[4j-1], 0xB) ⊻ aes_mul(current[4j], 0xD)
					tmp[3] = aes_mul(current[4j-3], 0xD) ⊻ aes_mul(current[4j-2], 0x9) ⊻ aes_mul(current[4j-1], 0xE) ⊻ aes_mul(current[4j], 0xB)
					tmp[4] = aes_mul(current[4j-3], 0xB) ⊻ aes_mul(current[4j-2], 0xD) ⊻ aes_mul(current[4j-1], 0x9) ⊻ aes_mul(current[4j], 0xE)
					current[4j-3] = tmp[1]
					current[4j-2] = tmp[2]
					current[4j-1] = tmp[3]
					current[4j] = tmp[4]
				end
			end
			# InvSubBytes
			for j in 1:16
				current[j] = INVSBOX[current[j]+1]
			end

			# InvShiftRows
			tmp1 = current[14]
			current[14] = current[10]
			current[10] = current[6]
			current[6] = current[2]
			current[2] = tmp1

			tmp1 = current[3]
			current[3] = current[11]
			current[11] = tmp1
			tmp1 = current[7]
			current[7] = current[15]
			current[15] = tmp1

			tmp1 = current[4]
			current[4] = current[8]
			current[8] = current[12]
			current[12] = current[16]
			current[16] = tmp1
		end
	end
	current
end

function AESDecryptBlock(block::Union{Array{UInt8, 1}, SubArray{UInt8}}, key::Array{UInt8})
	result = zeros(UInt8, 16)
	cache = AES128Cache()
	AESDecryptBlock!(result, block, key, cache)
	result
end

function AESDecryptBlock(block::Union{Array{UInt8, 1}, SubArray{UInt8}}, key::Array{UInt8}, cache::AES128Cache)
	result = zeros(UInt8, 16)
	AESDecryptBlock!(result, block, key, cache)
	result
end
