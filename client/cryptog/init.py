from client.cryptog import frodokex

seed = frodokex.frodokex_seed()

seed_file = "frodokex_seed.bin"
# Write the seed to the binary file
try:
    with open(seed_file, "wb") as f:
        f.write(seed)
    print(f"Seed saved to {seed_file}")
except Exception as e:
    print(f"Error writing seed to {seed_file}: {e}")
