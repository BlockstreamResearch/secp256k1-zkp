### See C function `shallue_van_de_woestijne`

load("secp256k1_params.sage")

b = F(7)
c = F(-3).nth_root(2)
d = (c - 1) / 2

def svdw(t):
    ## Compute candidate x values
    w  = c * t / (1 + b + t^2)
    x = [ F(0), F(0), F(0) ]
    x[0] = d - t * w
    x[1] = -(x[0] + 1)
    x[2] = 1 + (1 / w^2 if w != 0 else 0)

    # print()
    # print("On %2d" % t)
    # print(" x1 %064x" % x[0])
    # print(" x2 %064x" % x[1])
    #print(" x3 %064x" % x[2])

    ## Select which to use
    alph = jacobi_symbol(x[0]^3 + b, P)
    beta = jacobi_symbol(x[1]^3 + b, P)
    if alph == 1 and beta == 1:
        i = 0
    elif alph == 1 and beta == -1:
        i = 0
    elif alph == -1 and beta == 1:
        i = 1
    elif alph == -1 and beta == -1:
        i = 2
    else:
        assert False

    ## Expand to full point
    sign = 1 - 2 * (int(F(t)) % 2)
    ret_x = x[i]
    ret_y = sign * F(x[i]^3 + b).nth_root(2)
    return C.point((ret_x, ret_y))

def print_fe_const(f):
    print(f"SECP256K1_FE_CONST(", end="")
    print((7 * "0x%08x, " + "0x%08x") % tuple((int(f) >> (32 * (7 - (i % 8)))) & 0xffffffff for i in range(8)), end="")
    print(")", end="")

def print_ge_storage_const(g):
    print(f"SECP256K1_GE_STORAGE_CONST(", end="")
    print((15 * "0x%08x, " + "0x%08x") % tuple((int(g[int(i // 8)]) >> (32 * (7 - (i % 8)))) & 0xffffffff for i in range(16)), end="")
    print(")", end="")

## main
print("secp256k1_fe negc = ", end="")
print_fe_const(-c)
print(";")

print("secp256k1_fe d = ", end="")
print_fe_const(d)
print(";")

print()

print("secp256k1_ge_storage results[34] = {")
for i in range(0, 17):
    for s in [1, -1]:
        res = svdw(s*i)
        print_ge_storage_const(res)
        print(",")
print("}")
