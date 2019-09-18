@enum MODE::UInt8 begin
	ECB = 1
	CBC = 2
	CFB = 3
	OFB = 4
	CTR = 5
end

mutable struct AES{modeType,cacheType,keyType,ivType} <: AbstractCipher
	mode::modeType
	cache::cacheType
	key::keyType
	iv::ivType
end

function AES(;key_length=256,mode=CBC,key=keygen(key_length),iv=nothing)
	if !is_valid_key_length(key_length)
		error("$key_length is an invalid key length. Key length can be 128, 196 or 256.")
	end

	if get_key_length(key) !==  key_length
		error("Provided Key and Key Length do not agree.")
	end

	aes_key = convert_key(key, Val(key_length))

	cache = gen_cache(aes_key)

	if mode == CBC && iv isa Nothing
		iv = rand(UInt8, 16)
	end

	AES(mode,cache,aes_key,iv)
end
