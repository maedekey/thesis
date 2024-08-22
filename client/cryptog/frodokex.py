import ctypes
import numpy as np
import os

filePath = os.path.dirname(__file__)
rust_lib = ctypes.CDLL(filePath+'/frodokexp.dll')

N_BAR = 8
N = 1452
SEED_SIZE_BYTES = 32
SK_SIZE_BYTES = N * N_BAR * 2
F_SIZE_BYTES = N * N_BAR * 2
PK_SIZE_BYTES = N * N_BAR * 2
SS_SIZE_BYTES = 32


def frodokex_seed():
    frodokexp_gen_pp = rust_lib.frodokexp_gen_pp
    frodokexp_gen_pp.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    frodokexp_gen_pp.restype = None

    seed = (ctypes.c_ubyte * SEED_SIZE_BYTES)()
    frodokexp_gen_pp(seed)

    # Display the result
    return seed


def generate_A_Key(seed):
    frodokexp_gen_a = rust_lib.frodokexp_gen_a
    frodokexp_gen_a.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # seed
        ctypes.POINTER(ctypes.c_ubyte),  # sk_out
        ctypes.POINTER(ctypes.c_ubyte),  # f_out
        ctypes.POINTER(ctypes.c_ubyte),  # pk_out
    ]
    frodokexp_gen_a.restype = None

    # Define the sizes

    seed_array = (ctypes.c_ubyte * SEED_SIZE_BYTES)(*seed)

    # Allocate memory for sk_out, f_out, pk_out
    sk_out = (ctypes.c_ubyte * SK_SIZE_BYTES)()
    f_out = (ctypes.c_ubyte * F_SIZE_BYTES)()
    pk_out = (ctypes.c_ubyte * PK_SIZE_BYTES)()

    # Call frodokexp_gen_a
    frodokexp_gen_a(seed_array, sk_out, f_out, pk_out)

    # Convert results to numpy arrays
    sk_array = np.frombuffer(sk_out, dtype=np.uint8)
    f_array = np.frombuffer(f_out, dtype=np.uint8)
    pk_array = np.frombuffer(pk_out, dtype=np.uint8)

    return sk_array, f_array, pk_array


def generate_B_Key(seed):
    frodokexp_gen_b = rust_lib.frodokexp_gen_b
    frodokexp_gen_b.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # seed
        ctypes.POINTER(ctypes.c_ubyte),  # sk_out
        ctypes.POINTER(ctypes.c_ubyte),  # f_out
        ctypes.POINTER(ctypes.c_ubyte),  # pk_out
    ]
    frodokexp_gen_b.restype = None

    # Convert seed to ctypes array
    seed_array = (ctypes.c_ubyte * SEED_SIZE_BYTES)(*seed)

    # Allocate memory for sk_out, f_out, pk_out
    sk_out = (ctypes.c_ubyte * SK_SIZE_BYTES)()
    f_out = (ctypes.c_ubyte * F_SIZE_BYTES)()
    pk_out = (ctypes.c_ubyte * PK_SIZE_BYTES)()

    # Call frodokexp_gen_b
    frodokexp_gen_b(seed_array, sk_out, f_out, pk_out)

    # Convert results to numpy arrays
    sk_array = np.frombuffer(sk_out, dtype=np.uint8)
    f_array = np.frombuffer(f_out, dtype=np.uint8)
    pk_array = np.frombuffer(pk_out, dtype=np.uint8)

    return sk_array, f_array, pk_array


def encaps(b_a, sk_b):
    frodokexp_encaps = rust_lib.frodokexp_encaps
    frodokexp_encaps.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # b_a
        ctypes.POINTER(ctypes.c_ubyte),  # sk_b
        ctypes.POINTER(ctypes.c_ubyte),  # key_out
        ctypes.POINTER(ctypes.c_ulonglong),  # ct_out
    ]
    frodokexp_encaps.restype = None

    # Convert b_a and sk_b to ctypes arrays
    b_a_array = (ctypes.c_ubyte * PK_SIZE_BYTES)(*b_a)
    sk_b_array = (ctypes.c_ubyte * SK_SIZE_BYTES)(*sk_b)
    key_out = (ctypes.c_ubyte * SS_SIZE_BYTES)()

    ct_out = ctypes.c_ulonglong()

    # Call frodokexp_encaps
    frodokexp_encaps(b_a_array, sk_b_array, key_out, ct_out)

    # Convert key_out to a numpy array
    key_array = np.frombuffer(key_out, dtype=np.uint8)

    return key_array, ct_out


def decaps(b_b, sk_a, f_a, ct):
    frodokexp_decaps = rust_lib.frodokexp_decaps
    frodokexp_decaps.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # b_b
        ctypes.POINTER(ctypes.c_ubyte),  # sk_a
        ctypes.POINTER(ctypes.c_ubyte),  # f_a
        ctypes.POINTER(ctypes.c_ulonglong),  # ct
        ctypes.POINTER(ctypes.c_ubyte)  # key_out
    ]
    frodokexp_decaps.restype = None

    # Convert b_b, sk_a, f_a, and ct to ctypes arrays
    b_b_array = (ctypes.c_ubyte * len(b_b))(*b_b)
    sk_a_array = (ctypes.c_ubyte * len(sk_a))(*sk_a)
    f_a_array = (ctypes.c_ubyte * len(f_a))(*f_a)
    #ct_value = ctypes.c_ulonglong(ct)

    # Allocate memory for key_out
    key_out = (ctypes.c_ubyte * SS_SIZE_BYTES)()

    # Call frodokexp_decaps
    frodokexp_decaps(b_b_array, sk_a_array, f_a_array, ct, key_out)

    # Convert key_out to numpy array
    key_array = np.frombuffer(key_out, dtype=np.uint8)

    return key_array


seed = frodokex_seed()
