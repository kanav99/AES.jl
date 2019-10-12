mutable struct AESCipherText{modeType}
	data::Array{UInt8}
	iv::Array{UInt8}
	keylength::Int
	mode::modeType
	original_type::Type
end
