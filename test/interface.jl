using AES, Test

a=AES.AESBlock(rand(UInt8, 100), 3)
ac=copy(a)
@test ac == a
@test ac !== a
@test ac isa AES.AESBlock