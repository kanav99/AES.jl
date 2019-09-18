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

convert_key(key::AbstractAESKey, key_length) = key
convert_key(key::Array{UInt8,1}, ::Val{128}) = AES128Key(key)
convert_key(key::Array{UInt8,1}, ::Val{192}) = AES192Key(key)
convert_key(key::Array{UInt8,1}, ::Val{256}) = AES256Key(key)
convert_key(key::String, key_length) = convert_key(Array{UInt8}(key), key_length)
