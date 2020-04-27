using SafeTestsets

@time begin
	@time @safetestset "Block Encryption/Decryption tests" begin include("blocktest.jl") end
	@time @safetestset "CTR Mode tests" begin include("ctr.jl") end
end
