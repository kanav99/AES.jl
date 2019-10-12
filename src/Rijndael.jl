module Rijndael

	using StaticArrays, Random

	abstract type AbstractSymmetricKey end
	abstract type AbstractCipher end
	abstract type AbstractCipherCache end

	abstract type AbstractAESKey <: AbstractSymmetricKey end
	abstract type AbstractAESCache <: AbstractCipherCache end

	include("types/key.jl")
	include("types/cache.jl")
	include("types/ciphertext.jl")
	include("types/cipher.jl")
	include("utils.jl")
	include("block_encryption.jl")
	include("block_decryption.jl")
	include("modes/CBC.jl")
	include("modes/ECB.jl")
	include("modes/CTR.jl")
	include("modes/CFB.jl")
	include("encrypt.jl")
	include("decrypt.jl")

	export AES
	export AES128Key, AES192Key, AES256Key
	export AESCache
	export encrypt, decrypt

end # module
