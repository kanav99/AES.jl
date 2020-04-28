# Key types

"""
"""
struct AES256Key <: AbstractAESKey 
	key::Array{UInt8, 1}
end

"""
"""
struct AES192Key <: AbstractAESKey
	key::Array{UInt8, 1}
end

"""
"""
struct AES128Key <: AbstractAESKey
	key::Array{UInt8, 1}
end

@inline convert_key(key::AbstractAESKey, key_length) = key
@inline convert_key(key::Array{UInt8,1}, ::Val{128}) = AES128Key(key)
@inline convert_key(key::Array{UInt8,1}, ::Val{192}) = AES192Key(key)
@inline convert_key(key::Array{UInt8,1}, ::Val{256}) = AES256Key(key)
@inline convert_key(key::String, key_length) = convert_key(Array{UInt8}(key), key_length)

@inline Base.getindex(k::AbstractAESKey, i) = k.key[i]

@inline get_key_length(key::Array{UInt8}) = 8 * length(key)
@inline get_key_length(key::String) = 8 * length(key)
@inline get_key_length(key::AES128Key) = 128
@inline get_key_length(key::AES192Key) = 192
@inline get_key_length(key::AES256Key) = 256

# Cache Type
"""
"""
mutable struct CipherCache{kType,tmpType,modecacheType} <: AbstractAESCache
	""" registers to contain intermediate keys """
	K::kType
	""" temporary word """
	tmp::tmpType
	""" cache specific to mode """
	modecache::modecacheType
end

@inline get_intermediate_words(key::AES128Key) = @SArray[ zeros(UInt8, 4) for i in 1:4 ]
@inline get_intermediate_words(key::AES192Key) = @SArray[ zeros(UInt8, 4) for i in 1:6 ]
@inline get_intermediate_words(key::AES256Key) = @SArray[ zeros(UInt8, 4) for i in 1:4 ]

@inline get_modecache(m::Val{CTR}) = similar(Array{UInt8}, 16)
@inline get_modecache(m) = nothing

function gen_cache(key::AbstractAESKey, mode=CBC)
	K = get_intermediate_words(key)
	tmp = zeros(UInt8, 4)
	modecache = get_modecache(Val(mode))
	return CipherCache(K, tmp, modecache)
end

# Ciphertext type
"""
"""
mutable struct AESCipherText{ivType,modeType}
	data::Array{UInt8}
	iv::ivType
	keylength::Int
	mode::modeType
	original_type::Type
end

# Cipher Type

"""
"""
mutable struct AES{mode,cacheType,keyType} <: AbstractCipher
	cache::cacheType
	key::keyType
end

function AES(;key_length=128,mode=CBC,key=keygen(key_length))
	if !is_valid_key_length(key_length)
		error("$key_length is an invalid key length. Key length can be 128, 196 or 256.")
	end

	if get_key_length(key) !==  key_length
		error("Provided Key and Key Length do not agree.")
	end

	aes_key = convert_key(key, Val(key_length))

	cache = gen_cache(aes_key, mode)

	AES{mode,typeof(cache),typeof(aes_key)}(cache,aes_key)
end

@inline isecb(cipher::AES{m,c,k}) where {m,c,k} = m == ECB
@inline iscbc(cipher::AES{m,c,k}) where {m,c,k} = m == CBC
@inline iscfb(cipher::AES{m,c,k}) where {m,c,k} = m == CFB
@inline isofb(cipher::AES{m,c,k}) where {m,c,k} = m == OFB
@inline isctr(cipher::AES{m,c,k}) where {m,c,k} = m == CTR

@inline get_mode(cipher::AES{m,c,k}) where {m,c,k} = m
@inline get_key_length(cipher::AES) = get_key_length(cipher.key)

@inline needs_iv(cipher) = iscbc(cipher) || isctr(cipher)

# Block type

mutable struct AESBlock{dataType,offsetType} <: AbstractArray{UInt8, 1}
	data::dataType
	offset::offsetType
	function AESBlock(data, offset=1, len=16)
		new{typeof(data), typeof(offset)}(data, offset)
	end
end

function Base.getindex(block::B, i) where {B<:AESBlock}
	return UInt8(block.data[16*(block.offset - 1) + i])
end

function Base.setindex!(block::B, val, i) where {B<:AESBlock}
	block.data[16*(block.offset - 1) + i] = eltype(block.data)(val)
end

function Base.copyto!(block::B, arr::AbstractArray{T2,1}) where {B<:AESBlock, T2}
	for i in 1:16
		block.data[16*(block.offset - 1) + i] = eltype(block.data)(arr[i])
	end
end

@inline Base.size(block::AESBlock) = (16,)
@inline Base.length(block::AESBlock) = 16

increment!(block::B) where {B<:AESBlock} = block.offset += 1
