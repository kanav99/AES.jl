using SafeTestsets

@time begin
	@time @safetestset "Block Encryption/Decryption tests" begin include("blocktest.jl") end
	@time @safetestset "CBC Mode tests" begin include("cbc.jl") end
	@time @safetestset "CTR Mode tests" begin include("ctr.jl") end
	@time @safetestset "ECB Mode tests" begin include("ecb.jl") end
end
