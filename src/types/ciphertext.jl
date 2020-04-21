mutable struct AESCipherText{ivType,modeType}
	data::Array{UInt8}
	iv::ivType
	keylength::Int
	mode::modeType
	original_type::Type
end
