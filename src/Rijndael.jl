module Rijndael

	using StaticArrays, Random

	abstract type AbstractSymmetricKey end
	abstract type AbstractCipher end
	abstract type AbstractCipherCache end

	abstract type AbstractAESKey <: AbstractSymmetricKey end
	abstract type AbstractAESCache <: AbstractCipherCache end

	include("constants.jl")
	include("types.jl")
	include("block_encryption.jl")
	include("block_decryption.jl")
	include("modes/cbc.jl")
	include("modes/ctr.jl")
	include("modes/ecb.jl")
	include("encrypt.jl")
	include("decrypt.jl")

	export AES
	export AES128Key, AES192Key, AES256Key
	export AESCache
	export encrypt, decrypt

end # module
