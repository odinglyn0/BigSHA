# BigSHA - Arbitrarily large SHA-2 implementations

## Why would I need this? You don't.

## Why make this? Why not?

## How it works

This is a collection of SHA-2 variants that scale beyond the standard SHA-256/384/512 sizes. The implementation extends the SHA-2 algorithm to arbitrary output lengths by adjusting three parameters: internal state size, round count, and output digest length.

The base SHA-2 algorithm uses a Merkle-Damgård construction with 64-bit words. Each variant maintains the same core operations (rotate, shift, choice, majority functions) but scales the number of state variables and compression rounds proportionally to the target output size.

SHA-256 uses 4 state variables (256 bits total), 64 rounds, and outputs 256 bits.
SHA-512 uses 8 state variables (512 bits total), 80 rounds, and outputs 512 bits.
SHA-1024 uses 16 state variables (1024 bits total), 128 rounds, and outputs 1024 bits.

The pattern continues linearly. For an N-bit hash:
- State variables: N/64 (since each is a 64-bit word)
- Compression rounds: N/8 (empirically chosen scaling factor)
- Message schedule array: same as round count
- Output: N bits (N/64 words × 16 hex chars per word)

All variants use the same round constants (K array), cycling through them when the round count exceeds the array length. The initial hash values are extended by generating additional constants following the same pattern as the standard SHA-2 IVs.

Message padding remains consistent across all variants: append 0x80, pad with zeros until length ≡ 896 (mod 1024), then append the original message length as a 128-bit big-endian integer.

## Usage

```python
from src.sha.sha256.hash import sha256
from src.sha.sha1024.hash import sha1024
from src.sha.sha8192.hash import sha8192

# Basic hashing
hash_256 = sha256("your message here")
hash_1024 = sha1024("your message here")
hash_8192 = sha8192("your message here")

# With salt
hash_salted = sha256("your message", salt="random_salt")
```

Each variant is in its own module under `src/sha/{bits}/hash.py`. Import the function named `sha{bits}` from the corresponding module.

## Scaling

Currently implemented sizes: 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1408, 1536, 1664, 1792, 1920, 2048, 2176, 2304, 2432, 2560, 2688, 2816, 2944, 3072, 3328, 3456, 3584, 3840, 4096, 4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192.

The implementation scales in increments of 128 bits (2 state variables, 16 rounds). You could theoretically extend this to any multiple of 128 bits by following the pattern:

1. Create a new directory `src/sha/{N}/`
2. Copy an existing implementation
3. Adjust the class name to `SHA{N}`
4. Set state variables to `N/64` 64-bit words
5. Set round count to `N/8`
6. Extend the initial hash values array with additional constants
7. Update the compression function to handle the new state size
8. Then PR it because why not?

Performance degrades linearly with output size since round count scales proportionally. SHA-8192 takes roughly 32x longer than SHA-256 to compute. Memory usage is negligible - the message schedule array is the largest structure and scales with round count.

Theoretical SHA-8192 completed a hash (1 MiB input) in <2ms on a modern CPU.

## Security considerations

DON'T USE THIS IN PROD!!! These havent been cryptanalyzed and are as they are advertised - "experimental", do not use this in prod or secure environs, you have been warned..