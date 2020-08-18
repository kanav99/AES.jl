"""
Note: you can pass `result` and `block` as same pointers
"""
function AESEncryptBlock!(result::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, block::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, key) where {B<:AESBlock}
	cache = gen_cache(key)
	AESEncryptBlock!(result, block, key, cache)
end

function AESEncryptBlock(block::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, key, cache) where {B<:AESBlock}
	result = zeros(UInt8, 16)
	AESEncryptBlock!(result, block, key, cache)
	result
end

function AESEncryptBlock(block::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, key) where {B<:AESBlock}
	result = zeros(UInt8, 16)
	cache = gen_cache(key)
	AESEncryptBlock!(result, block, key, cache)
	result
end

function AESEncryptBlock!(result::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, block::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, key::AES128Key, cache::CipherCache) where {B<:AESBlock}
	current = result
	copyto!(current, block)
	K = cache.K
	tmp = cache.tmp

	# Copy Key
	for i in 1:4
		for j in 1:4
			K[i][j] = key[4i+j-4]
		end
	end
	# Start Rounds
	for i in 1:11
		if i > 1
			#GenRoundKey
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
			# SubBytes
			for j in 1:16
				current[j] = SBOX[current[j]+1]
			end
			# ShiftRows
			tmp1 = current[2]
			current[2] = current[6]
			current[6] = current[10]
			current[10] = current[14]
			current[14] = tmp1

			tmp1 = current[3]
			current[3] = current[11]
			current[11] = tmp1
			tmp1 = current[7]
			current[7] = current[15]
			current[15] = tmp1

			tmp1 = current[16]
			current[16] = current[12]
			current[12] = current[8]
			current[8] = current[4]
			current[4] = tmp1
			# MixColumns
			if i != 11
				for j in 1:4
					tmp[1] = aes_mul(current[4j-3], 0x2) ⊻ aes_mul(current[4j-2], 0x3) ⊻ aes_mul(current[4j-1], 0x1) ⊻ aes_mul(current[4j], 0x1)
					tmp[2] = aes_mul(current[4j-3], 0x1) ⊻ aes_mul(current[4j-2], 0x2) ⊻ aes_mul(current[4j-1], 0x3) ⊻ aes_mul(current[4j], 0x1)
					tmp[3] = aes_mul(current[4j-3], 0x1) ⊻ aes_mul(current[4j-2], 0x1) ⊻ aes_mul(current[4j-1], 0x2) ⊻ aes_mul(current[4j], 0x3)
					tmp[4] = aes_mul(current[4j-3], 0x3) ⊻ aes_mul(current[4j-2], 0x1) ⊻ aes_mul(current[4j-1], 0x1) ⊻ aes_mul(current[4j], 0x2)
					current[4j-3] = tmp[1]
					current[4j-2] = tmp[2]
					current[4j-1] = tmp[3]
					current[4j  ] = tmp[4]
				end
			end
		end
		# AddRoundKey
		for j in 1:4
			for k in 1:4
				current[4j+k-4] = current[4j+k-4] ⊻ K[j][k]
			end
		end
	end
	current
end

function AESEncryptBlock!(result::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, block::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, key::AES192Key, cache::CipherCache) where {B<:AESBlock}
	current = result
	copyto!(current, block)
	K = cache.K
	tmp = cache.tmp

	# Copy Key
	for i in 1:6 #DIFF
		for j in 1:4
			K[i][j] = key[4i+j-4]
		end
	end
	# Start Rounds
	rid = 1
	for i in 1:13 #DIFF
		if i > 1
			#GenRoundKey
			if (i % 3 == 2) || (i % 3 == 1)
				copyto!(tmp, K[6]) #DIFF
				for j in 1:4
					tmp[j] = SBOX[tmp[j]+1]
				end
				tmp1 = tmp[1]
				tmp[1] = tmp[2]
				tmp[2] = tmp[3]
				tmp[3] = tmp[4]
				tmp[4] = tmp1
				K[1] .= K[1] .⊻ tmp
				K[1][1] = K[1][1] ⊻ RCON[rid]
				rid += 1
				K[2] .= K[2] .⊻ K[1]
			end
			if (i % 3 == 0) || (i % 3 == 1)
				K[3] .= K[3] .⊻ K[2]
				K[4] .= K[4] .⊻ K[3]
				K[5] .= K[5] .⊻ K[4] #DIFF
				K[6] .= K[6] .⊻ K[5] #DIFF
			end
			# SubBytes
			for j in 1:16
				current[j] = SBOX[current[j]+1]
			end
			# ShiftRows
			tmp1 = current[2]
			current[2] = current[6]
			current[6] = current[10]
			current[10] = current[14]
			current[14] = tmp1

			tmp1 = current[3]
			current[3] = current[11]
			current[11] = tmp1
			tmp1 = current[7]
			current[7] = current[15]
			current[15] = tmp1

			tmp1 = current[16]
			current[16] = current[12]
			current[12] = current[8]
			current[8] = current[4]
			current[4] = tmp1
			# MixColumns
			if i != 13 #DIFF
				for j in 1:4
					tmp[1] = aes_mul(current[4j-3], 0x2) ⊻ aes_mul(current[4j-2], 0x3) ⊻ aes_mul(current[4j-1], 0x1) ⊻ aes_mul(current[4j], 0x1)
					tmp[2] = aes_mul(current[4j-3], 0x1) ⊻ aes_mul(current[4j-2], 0x2) ⊻ aes_mul(current[4j-1], 0x3) ⊻ aes_mul(current[4j], 0x1)
					tmp[3] = aes_mul(current[4j-3], 0x1) ⊻ aes_mul(current[4j-2], 0x1) ⊻ aes_mul(current[4j-1], 0x2) ⊻ aes_mul(current[4j], 0x3)
					tmp[4] = aes_mul(current[4j-3], 0x3) ⊻ aes_mul(current[4j-2], 0x1) ⊻ aes_mul(current[4j-1], 0x1) ⊻ aes_mul(current[4j], 0x2)
					current[4j-3] = tmp[1]
					current[4j-2] = tmp[2]
					current[4j-1] = tmp[3]
					current[4j  ] = tmp[4]
				end
			end
		end
		# AddRoundKey
		if i % 3 == 1
			for j in 1:4
				for k in 1:4
					current[4j+k-4] = current[4j+k-4] ⊻ K[j][k]
				end
			end
		elseif i % 3 == 2
			for j in 1:4
				for k in 1:4
					current[4j+k-4] = current[4j+k-4] ⊻ K[(j + 3) % 6 + 1][k]
				end
			end
		else
			for j in 1:4
				for k in 1:4
					current[4j+k-4] = current[4j+k-4] ⊻ K[j + 2][k]
				end
			end
		end
	end
	current
end

function AESEncryptBlock!(result::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, block::Union{Array{UInt8, 1}, SubArray{UInt8}, B}, key::AES256Key, cache::CipherCache) where {B<:AESBlock}
	current = result
	copyto!(current, block)
	K = cache.K
	tmp = cache.tmp

	# Copy Key
	for i in 1:8
		for j in 1:4
			K[i][j] = key[4i+j-4]
		end
	end
	# Start Rounds
	for i in 1:15
		if i > 1
			#GenRoundKey
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
			# SubBytes
			for j in 1:16
				current[j] = SBOX[current[j]+1]
			end
			# ShiftRows
			tmp1 = current[2]
			current[2] = current[6]
			current[6] = current[10]
			current[10] = current[14]
			current[14] = tmp1

			tmp1 = current[3]
			current[3] = current[11]
			current[11] = tmp1
			tmp1 = current[7]
			current[7] = current[15]
			current[15] = tmp1

			tmp1 = current[16]
			current[16] = current[12]
			current[12] = current[8]
			current[8] = current[4]
			current[4] = tmp1
			# MixColumns
			if i != 15
				for j in 1:4
					tmp[1] = aes_mul(current[4j-3], 0x2) ⊻ aes_mul(current[4j-2], 0x3) ⊻ aes_mul(current[4j-1], 0x1) ⊻ aes_mul(current[4j], 0x1)
					tmp[2] = aes_mul(current[4j-3], 0x1) ⊻ aes_mul(current[4j-2], 0x2) ⊻ aes_mul(current[4j-1], 0x3) ⊻ aes_mul(current[4j], 0x1)
					tmp[3] = aes_mul(current[4j-3], 0x1) ⊻ aes_mul(current[4j-2], 0x1) ⊻ aes_mul(current[4j-1], 0x2) ⊻ aes_mul(current[4j], 0x3)
					tmp[4] = aes_mul(current[4j-3], 0x3) ⊻ aes_mul(current[4j-2], 0x1) ⊻ aes_mul(current[4j-1], 0x1) ⊻ aes_mul(current[4j], 0x2)
					current[4j-3] = tmp[1]
					current[4j-2] = tmp[2]
					current[4j-1] = tmp[3]
					current[4j  ] = tmp[4]
				end
			end
		end
		# AddRoundKey
		for j in 1:4
			for k in 1:4
				current[4j+k-4] = current[4j+k-4] ⊻ K[j][k]
			end
		end
	end
	current
end
