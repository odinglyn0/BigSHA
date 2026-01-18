"""Test BigSHA implementations"""

import sys
import importlib.util

def load_hash_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

sha256_module = load_hash_module('src/sha/256/hash.py', 'sha256_hash')
sha384_module = load_hash_module('src/sha/384/hash.py', 'sha384_hash')
sha512_module = load_hash_module('src/sha/512/hash.py', 'sha512_hash')
sha640_module = load_hash_module('src/sha/640/hash.py', 'sha640_hash')
sha768_module = load_hash_module('src/sha/768/hash.py', 'sha768_hash')
sha896_module = load_hash_module('src/sha/896/hash.py', 'sha896_hash')
sha1024_module = load_hash_module('src/sha/1024/hash.py', 'sha1024_hash')
sha1152_module = load_hash_module('src/sha/1152/hash.py', 'sha1152_hash')
sha1280_module = load_hash_module('src/sha/1280/hash.py', 'sha1280_hash')
sha1408_module = load_hash_module('src/sha/1408/hash.py', 'sha1408_hash')
sha1536_module = load_hash_module('src/sha/1536/hash.py', 'sha1536_hash')
sha1664_module = load_hash_module('src/sha/1664/hash.py', 'sha1664_hash')
sha1792_module = load_hash_module('src/sha/1792/hash.py', 'sha1792_hash')
sha1920_module = load_hash_module('src/sha/1920/hash.py', 'sha1920_hash')
sha2048_module = load_hash_module('src/sha/2048/hash.py', 'sha2048_hash')
sha2176_module = load_hash_module('src/sha/2176/hash.py', 'sha2176_hash')
sha2304_module = load_hash_module('src/sha/2304/hash.py', 'sha2304_hash')
sha2432_module = load_hash_module('src/sha/2432/hash.py', 'sha2432_hash')
sha2560_module = load_hash_module('src/sha/2560/hash.py', 'sha2560_hash')
sha2688_module = load_hash_module('src/sha/2688/hash.py', 'sha2688_hash')
sha2816_module = load_hash_module('src/sha/2816/hash.py', 'sha2816_hash')
sha2944_module = load_hash_module('src/sha/2944/hash.py', 'sha2944_hash')
sha3072_module = load_hash_module('src/sha/3072/hash.py', 'sha3072_hash')
sha3328_module = load_hash_module('src/sha/3328/hash.py', 'sha3328_hash')
sha3456_module = load_hash_module('src/sha/3456/hash.py', 'sha3456_hash')
sha3584_module = load_hash_module('src/sha/3584/hash.py', 'sha3584_hash')
sha3840_module = load_hash_module('src/sha/3840/hash.py', 'sha3840_hash')
sha4096_module = load_hash_module('src/sha/4096/hash.py', 'sha4096_hash')
sha4608_module = load_hash_module('src/sha/4608/hash.py', 'sha4608_hash')
sha5120_module = load_hash_module('src/sha/5120/hash.py', 'sha5120_hash')
sha5632_module = load_hash_module('src/sha/5632/hash.py', 'sha5632_hash')
sha6144_module = load_hash_module('src/sha/6144/hash.py', 'sha6144_hash')
sha6656_module = load_hash_module('src/sha/6656/hash.py', 'sha6656_hash')
sha7168_module = load_hash_module('src/sha/7168/hash.py', 'sha7168_hash')
sha7680_module = load_hash_module('src/sha/7680/hash.py', 'sha7680_hash')
sha8192_module = load_hash_module('src/sha/8192/hash.py', 'sha8192_hash')

sha256 = sha256_module.sha256
sha384 = sha384_module.sha384
sha512 = sha512_module.sha512
sha640 = sha640_module.sha640
sha768 = sha768_module.sha768
sha896 = sha896_module.sha896
sha1024 = sha1024_module.sha1024
sha1152 = sha1152_module.sha1152
sha1280 = sha1280_module.sha1280
sha1408 = sha1408_module.sha1408
sha1536 = sha1536_module.sha1536
sha1664 = sha1664_module.sha1664
sha1792 = sha1792_module.sha1792
sha1920 = sha1920_module.sha1920
sha2048 = sha2048_module.sha2048
sha2176 = sha2176_module.sha2176
sha2304 = sha2304_module.sha2304
sha2432 = sha2432_module.sha2432
sha2560 = sha2560_module.sha2560
sha2688 = sha2688_module.sha2688
sha2816 = sha2816_module.sha2816
sha2944 = sha2944_module.sha2944
sha3072 = sha3072_module.sha3072
sha3328 = sha3328_module.sha3328
sha3456 = sha3456_module.sha3456
sha3584 = sha3584_module.sha3584
sha3840 = sha3840_module.sha3840
sha4096 = sha4096_module.sha4096
sha4608 = sha4608_module.sha4608
sha5120 = sha5120_module.sha5120
sha5632 = sha5632_module.sha5632
sha6144 = sha6144_module.sha6144
sha6656 = sha6656_module.sha6656
sha7168 = sha7168_module.sha7168
sha7680 = sha7680_module.sha7680
sha8192 = sha8192_module.sha8192

def test_alphanumeric():
    test_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
    
    print("Testing SHA Implementation")
    print("=" * 80)
    print(f"Input: {test_string}")
    print(f"Length: {len(test_string)} characters")
    print()
    
    for name, func in [
        ("SHA-256", sha256),
        ("SHA-384", sha384),
        ("SHA-512", sha512),
        ("SHA-640", sha640),
        ("SHA-768", sha768),
        ("SHA-896", sha896),
        ("SHA-1024", sha1024),
        ("SHA-1152", sha1152),
        ("SHA-1280", sha1280),
        ("SHA-1408", sha1408),
        ("SHA-1536", sha1536),
        ("SHA-1664", sha1664),
        ("SHA-1792", sha1792),
        ("SHA-1920", sha1920),
        ("SHA-2048", sha2048),
        ("SHA-2176", sha2176),
        ("SHA-2304", sha2304),
        ("SHA-2432", sha2432),
        ("SHA-2560", sha2560),
        ("SHA-2688", sha2688),
        ("SHA-2816", sha2816),
        ("SHA-2944", sha2944),
        ("SHA-3072", sha3072),
        ("SHA-3328", sha3328),
        ("SHA-3456", sha3456),
        ("SHA-3584", sha3584),
        ("SHA-3840", sha3840),
        ("SHA-4096", sha4096),
        ("SHA-4608", sha4608),
        ("SHA-5120", sha5120),
        ("SHA-5632", sha5632),
        ("SHA-6144", sha6144),
        ("SHA-6656", sha6656),
        ("SHA-7168", sha7168),
        ("SHA-7680", sha7680),
        ("SHA-8192", sha8192)
    ]:
        result = func(test_string)
        print(f"{name} Hash:")
        print(result)
        print()
    
    print("=" * 80)


if __name__ == "__main__":
    test_alphanumeric()
