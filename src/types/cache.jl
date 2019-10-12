mutable struct AES128Cache{kType,tmpType} <: AbstractAESCache
	K::kType
	tmp::tmpType
	function AES128Cache()
		K = @SArray[ zeros(UInt8, 4) for i in 1:4 ]
		tmp = zeros(UInt8, 4)
		new{typeof(K),typeof(tmp)}(K,tmp)
	end
end

mutable struct AES192Cache{kType,tmpType} <: AbstractAESCache
	K::kType
	tmp::tmpType
	function AES192Cache()
		K = @SArray[ zeros(UInt8, 4) for i in 1:6 ]
		tmp = zeros(UInt8, 4)
		new{typeof(K),typeof(tmp)}(K,tmp)
	end
end

mutable struct AES256Cache{kType,tmpType} <: AbstractAESCache
	K::kType
	tmp::tmpType
	function AES256Cache()
		K = @SArray[ zeros(UInt8, 4) for i in 1:4 ]
		tmp = zeros(UInt8, 4)
		new{typeof(K),typeof(tmp)}(K,tmp)
	end
end


gen_cache(key::AES128Key) = AES128Cache()
gen_cache(key::AES192Key) = AES192Cache()
gen_cache(key::AES256Key) = AES256Cache()
