class SHA6656:
    """SHA-6656 hash implementation with optional salt support."""

    K = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        0x7e3d36d1b812511a, 0x8e6c9b0e6f3e1f9d, 0x9f0a1c2e3d4b5a6c, 0xa1b2c3d4e5f60718,
        0xb2c3d4e5f6071829, 0xc3d4e5f607182930, 0xd4e5f60718293041, 0xe5f6071829304152,
        0xf607182930415263, 0x0718293041526374, 0x1829304152637485, 0x2930415263748596,
        0x30415263748596a7, 0x415263748596a7b8, 0x5263748596a7b8c9, 0x63748596a7b8c9da,
        0x748596a7b8c9daeb, 0x8596a7b8c9daebfc, 0x96a7b8c9daebfc0d, 0xa7b8c9daebfc0d1e,
        0xb8c9daebfc0d1e2f, 0xc9daebfc0d1e2f30, 0xdaebfc0d1e2f3041, 0xebfc0d1e2f304152,
        0xfc0d1e2f30415263, 0x0d1e2f3041526374, 0x1e2f304152637485, 0x2f30415263748596,
        0x304152637485a6b7, 0x4152637485a6b7c8, 0x52637485a6b7c8d9, 0x637485a6b7c8d9ea,
        0x7485a6b7c8d9eafb, 0x85a6b7c8d9eafb0c, 0xa6b7c8d9eafb0c1d, 0xb7c8d9eafb0c1d2e
    ]
    
    def __init__(self):
        """Init SHA-6656 with initial hash values."""
        self.h = [
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
            0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
            0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
            0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
            0x7e3d36d1b812511a, 0x8e6c9b0e6f3e1f9d, 0x9f0a1c2e3d4b5a6c, 0xa1b2c3d4e5f60718,
            0xb2c3d4e5f6071829, 0xc3d4e5f607182930, 0xd4e5f60718293041, 0xe5f6071829304152,
            0xf607182930415263, 0x0718293041526374, 0x1829304152637485, 0x2930415263748596,
            0x30415263748596a7, 0x415263748596a7b8, 0x5263748596a7b8c9, 0x63748596a7b8c9da,
            0x748596a7b8c9daeb, 0x8596a7b8c9daebfc, 0x96a7b8c9daebfc0d, 0xa7b8c9daebfc0d1e,
            0xb8c9daebfc0d1e2f, 0xc9daebfc0d1e2f30, 0xdaebfc0d1e2f3041, 0xebfc0d1e2f304152,
            0xfc0d1e2f30415263, 0x0d1e2f3041526374, 0x1e2f304152637485, 0x2f30415263748596,
            0x304152637485a6b7, 0x4152637485a6b7c8, 0x52637485a6b7c8d9, 0x637485a6b7c8d9ea
        ]
    
    @staticmethod
    def _rotr(n, b):
        """Rotate right operation."""
        return ((n >> b) | (n << (64 - b))) & 0xFFFFFFFFFFFFFFFF
    
    @staticmethod
    def _shr(n, b):
        """Shift right operation."""
        return n >> b
    
    def _ch(self, x, y, z):
        """Choice function."""
        return (x & y) ^ (~x & z)
    
    def _maj(self, x, y, z):
        """Majority function."""
        return (x & y) ^ (x & z) ^ (y & z)
    
    def _sigma0(self, x):
        """Sigma0 function."""
        return self._rotr(x, 28) ^ self._rotr(x, 34) ^ self._rotr(x, 39)
    
    def _sigma1(self, x):
        """Sigma1 function."""
        return self._rotr(x, 14) ^ self._rotr(x, 18) ^ self._rotr(x, 41)
    
    def _gamma0(self, x):
        """Gamma0 function."""
        return self._rotr(x, 1) ^ self._rotr(x, 8) ^ self._shr(x, 7)
    
    def _gamma1(self, x):
        """Gamma1 function."""
        return self._rotr(x, 19) ^ self._rotr(x, 61) ^ self._shr(x, 6)

    def _pad_message(self, message):
        """Pad message according to SHA-6656 specification."""
        msg_len = len(message)
        message += b'\x80'

        while (len(message) * 8) % 1024 != 896:
            message += b'\x00'

        message += (msg_len * 8).to_bytes(16, byteorder='big')
        
        return message
    
    def _process_chunk(self, chunk):
        """Process an n-bit chunk."""

        w = [0] * 1664
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*8:(i+1)*8], byteorder='big')

        for i in range(16, 1664):
            w[i] = (self._gamma1(w[i-2]) + w[i-7] + self._gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFFFFFFFFFF

        a, b, c, d, e, f, g, h, i_val, j, k, l, m, n, o, p, q, r, s, t, u, v, w_val, x, y, z, aa, ab, ac, ad, ae, af, ag, ah, ai, aj, ak, al, am, an, ao, ap, aq, ar, as_val, at, au, av, aw, ax, ay, az, ba, bb, bc, bd, be, bf, bg, bh, bi, bj, bk, bl, bm, bn, bo, bp, bq, br, bs, bt, bu, bv, bw, bx, by, bz, ca, cb, cc, cd, ce, cf, cg, ch, ci, cj, ck, cl, cm, cn, co, cp, cq, cr, cs, ct, cu, cv, cw, cx, cy, cz = self.h

        for i in range(1664):
            t1 = (cz + self._sigma1(e) + self._ch(e, f, g) + self.K[i % len(self.K)] + w[i]) & 0xFFFFFFFFFFFFFFFF
            t2 = (self._sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFFFFFFFFFF
            cz = cy
            cy = cx
            cx = cw
            cw = cv
            cv = cu
            cu = ct
            ct = cs
            cs = cr
            cr = cq
            cq = cp
            cp = co
            co = cn
            cn = cm
            cm = cl
            cl = ck
            ck = cj
            cj = ci
            ci = ch
            ch = cg
            cg = cf
            cf = ce
            ce = cd
            cd = cc
            cc = cb
            cb = ca
            ca = bz
            bz = by
            by = bx
            bx = bw
            bw = bv
            bv = bu
            bu = bt
            bt = bs
            bs = br
            br = bq
            bq = bp
            bp = bo
            bo = bn
            bn = bm
            bm = bl
            bl = bk
            bk = bj
            bj = bi
            bi = bh
            bh = bg
            bg = bf
            bf = be
            be = bd
            bd = bc
            bc = bb
            bb = ba
            ba = az
            az = ay
            ay = ax
            ax = aw
            aw = av
            av = au
            au = at
            at = as_val
            as_val = ar
            ar = aq
            aq = ap
            ap = ao
            ao = an
            an = am
            am = al
            al = ak
            ak = aj
            aj = ai
            ai = ah
            ah = ag
            ag = af
            af = ae
            ae = ad
            ad = ac
            ac = ab
            ab = aa
            aa = z
            z = y
            y = x
            x = w_val
            w_val = v
            v = u
            u = t
            t = s
            s = r
            r = q
            q = p
            p = o
            o = n
            n = m
            m = l
            l = k
            k = j
            j = i_val
            i_val = h
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFFFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFFFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFFFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFFFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFFFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFFFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFFFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFFFFFFFFFF
        self.h[8] = (self.h[8] + i_val) & 0xFFFFFFFFFFFFFFFF
        self.h[9] = (self.h[9] + j) & 0xFFFFFFFFFFFFFFFF
        self.h[10] = (self.h[10] + k) & 0xFFFFFFFFFFFFFFFF
        self.h[11] = (self.h[11] + l) & 0xFFFFFFFFFFFFFFFF
        self.h[12] = (self.h[12] + m) & 0xFFFFFFFFFFFFFFFF
        self.h[13] = (self.h[13] + n) & 0xFFFFFFFFFFFFFFFF
        self.h[14] = (self.h[14] + o) & 0xFFFFFFFFFFFFFFFF
        self.h[15] = (self.h[15] + p) & 0xFFFFFFFFFFFFFFFF
        self.h[16] = (self.h[16] + q) & 0xFFFFFFFFFFFFFFFF
        self.h[17] = (self.h[17] + r) & 0xFFFFFFFFFFFFFFFF
        self.h[18] = (self.h[18] + s) & 0xFFFFFFFFFFFFFFFF
        self.h[19] = (self.h[19] + t) & 0xFFFFFFFFFFFFFFFF
        self.h[20] = (self.h[20] + u) & 0xFFFFFFFFFFFFFFFF
        self.h[21] = (self.h[21] + v) & 0xFFFFFFFFFFFFFFFF
        self.h[22] = (self.h[22] + w_val) & 0xFFFFFFFFFFFFFFFF
        self.h[23] = (self.h[23] + x) & 0xFFFFFFFFFFFFFFFF
        self.h[24] = (self.h[24] + y) & 0xFFFFFFFFFFFFFFFF
        self.h[25] = (self.h[25] + z) & 0xFFFFFFFFFFFFFFFF
        self.h[26] = (self.h[26] + aa) & 0xFFFFFFFFFFFFFFFF
        self.h[27] = (self.h[27] + ab) & 0xFFFFFFFFFFFFFFFF
        self.h[28] = (self.h[28] + ac) & 0xFFFFFFFFFFFFFFFF
        self.h[29] = (self.h[29] + ad) & 0xFFFFFFFFFFFFFFFF
        self.h[30] = (self.h[30] + ae) & 0xFFFFFFFFFFFFFFFF
        self.h[31] = (self.h[31] + af) & 0xFFFFFFFFFFFFFFFF
        self.h[32] = (self.h[32] + ag) & 0xFFFFFFFFFFFFFFFF
        self.h[33] = (self.h[33] + ah) & 0xFFFFFFFFFFFFFFFF
        self.h[34] = (self.h[34] + ai) & 0xFFFFFFFFFFFFFFFF
        self.h[35] = (self.h[35] + aj) & 0xFFFFFFFFFFFFFFFF
        self.h[36] = (self.h[36] + ak) & 0xFFFFFFFFFFFFFFFF
        self.h[37] = (self.h[37] + al) & 0xFFFFFFFFFFFFFFFF
        self.h[38] = (self.h[38] + am) & 0xFFFFFFFFFFFFFFFF
        self.h[39] = (self.h[39] + an) & 0xFFFFFFFFFFFFFFFF
        self.h[40] = (self.h[40] + ao) & 0xFFFFFFFFFFFFFFFF
        self.h[41] = (self.h[41] + ap) & 0xFFFFFFFFFFFFFFFF
        self.h[42] = (self.h[42] + aq) & 0xFFFFFFFFFFFFFFFF
        self.h[43] = (self.h[43] + ar) & 0xFFFFFFFFFFFFFFFF
        self.h[44] = (self.h[44] + as_val) & 0xFFFFFFFFFFFFFFFF
        self.h[45] = (self.h[45] + at) & 0xFFFFFFFFFFFFFFFF
        self.h[46] = (self.h[46] + au) & 0xFFFFFFFFFFFFFFFF
        self.h[47] = (self.h[47] + av) & 0xFFFFFFFFFFFFFFFF
        self.h[48] = (self.h[48] + aw) & 0xFFFFFFFFFFFFFFFF
        self.h[49] = (self.h[49] + ax) & 0xFFFFFFFFFFFFFFFF
        self.h[50] = (self.h[50] + ay) & 0xFFFFFFFFFFFFFFFF
        self.h[51] = (self.h[51] + az) & 0xFFFFFFFFFFFFFFFF
        self.h[52] = (self.h[52] + ba) & 0xFFFFFFFFFFFFFFFF
        self.h[53] = (self.h[53] + bb) & 0xFFFFFFFFFFFFFFFF
        self.h[54] = (self.h[54] + bc) & 0xFFFFFFFFFFFFFFFF
        self.h[55] = (self.h[55] + bd) & 0xFFFFFFFFFFFFFFFF
        self.h[56] = (self.h[56] + be) & 0xFFFFFFFFFFFFFFFF
        self.h[57] = (self.h[57] + bf) & 0xFFFFFFFFFFFFFFFF
        self.h[58] = (self.h[58] + bg) & 0xFFFFFFFFFFFFFFFF
        self.h[59] = (self.h[59] + bh) & 0xFFFFFFFFFFFFFFFF
        self.h[60] = (self.h[60] + bi) & 0xFFFFFFFFFFFFFFFF
        self.h[61] = (self.h[61] + bj) & 0xFFFFFFFFFFFFFFFF
        self.h[62] = (self.h[62] + bk) & 0xFFFFFFFFFFFFFFFF
        self.h[63] = (self.h[63] + bl) & 0xFFFFFFFFFFFFFFFF
        self.h[64] = (self.h[64] + bm) & 0xFFFFFFFFFFFFFFFF
        self.h[65] = (self.h[65] + bn) & 0xFFFFFFFFFFFFFFFF
        self.h[66] = (self.h[66] + bo) & 0xFFFFFFFFFFFFFFFF
        self.h[67] = (self.h[67] + bp) & 0xFFFFFFFFFFFFFFFF
        self.h[68] = (self.h[68] + bq) & 0xFFFFFFFFFFFFFFFF
        self.h[69] = (self.h[69] + br) & 0xFFFFFFFFFFFFFFFF
        self.h[70] = (self.h[70] + bs) & 0xFFFFFFFFFFFFFFFF
        self.h[71] = (self.h[71] + bt) & 0xFFFFFFFFFFFFFFFF
        self.h[72] = (self.h[72] + bu) & 0xFFFFFFFFFFFFFFFF
        self.h[73] = (self.h[73] + bv) & 0xFFFFFFFFFFFFFFFF
        self.h[74] = (self.h[74] + bw) & 0xFFFFFFFFFFFFFFFF
        self.h[75] = (self.h[75] + bx) & 0xFFFFFFFFFFFFFFFF
        self.h[76] = (self.h[76] + by) & 0xFFFFFFFFFFFFFFFF
        self.h[77] = (self.h[77] + bz) & 0xFFFFFFFFFFFFFFFF
        self.h[78] = (self.h[78] + ca) & 0xFFFFFFFFFFFFFFFF
        self.h[79] = (self.h[79] + cb) & 0xFFFFFFFFFFFFFFFF
        self.h[80] = (self.h[80] + cc) & 0xFFFFFFFFFFFFFFFF
        self.h[81] = (self.h[81] + cd) & 0xFFFFFFFFFFFFFFFF
        self.h[82] = (self.h[82] + ce) & 0xFFFFFFFFFFFFFFFF
        self.h[83] = (self.h[83] + cf) & 0xFFFFFFFFFFFFFFFF
        self.h[84] = (self.h[84] + cg) & 0xFFFFFFFFFFFFFFFF
        self.h[85] = (self.h[85] + ch) & 0xFFFFFFFFFFFFFFFF
        self.h[86] = (self.h[86] + ci) & 0xFFFFFFFFFFFFFFFF
        self.h[87] = (self.h[87] + cj) & 0xFFFFFFFFFFFFFFFF
        self.h[88] = (self.h[88] + ck) & 0xFFFFFFFFFFFFFFFF
        self.h[89] = (self.h[89] + cl) & 0xFFFFFFFFFFFFFFFF
        self.h[90] = (self.h[90] + cm) & 0xFFFFFFFFFFFFFFFF
        self.h[91] = (self.h[91] + cn) & 0xFFFFFFFFFFFFFFFF
        self.h[92] = (self.h[92] + co) & 0xFFFFFFFFFFFFFFFF
        self.h[93] = (self.h[93] + cp) & 0xFFFFFFFFFFFFFFFF
        self.h[94] = (self.h[94] + cq) & 0xFFFFFFFFFFFFFFFF
        self.h[95] = (self.h[95] + cr) & 0xFFFFFFFFFFFFFFFF
        self.h[96] = (self.h[96] + cs) & 0xFFFFFFFFFFFFFFFF
        self.h[97] = (self.h[97] + ct) & 0xFFFFFFFFFFFFFFFF
        self.h[98] = (self.h[98] + cu) & 0xFFFFFFFFFFFFFFFF
        self.h[99] = (self.h[99] + cv) & 0xFFFFFFFFFFFFFFFF
        self.h[100] = (self.h[100] + cw) & 0xFFFFFFFFFFFFFFFF
        self.h[101] = (self.h[101] + cx) & 0xFFFFFFFFFFFFFFFF
        self.h[102] = (self.h[102] + cy) & 0xFFFFFFFFFFFFFFFF
        self.h[103] = (self.h[103] + cz) & 0xFFFFFFFFFFFFFFFF
    
    def hash(self, message):
        """
        Compute SHA-6656 hash of message.
        
        Args:
            message: bytes or str to hash
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        self.h = [
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
            0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
            0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
            0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
            0x7e3d36d1b812511a, 0x8e6c9b0e6f3e1f9d, 0x9f0a1c2e3d4b5a6c, 0xa1b2c3d4e5f60718,
            0xb2c3d4e5f6071829, 0xc3d4e5f607182930, 0xd4e5f60718293041, 0xe5f6071829304152,
            0xf607182930415263, 0x0718293041526374, 0x1829304152637485, 0x2930415263748596,
            0x30415263748596a7, 0x415263748596a7b8, 0x5263748596a7b8c9, 0x63748596a7b8c9da,
            0x748596a7b8c9daeb, 0x8596a7b8c9daebfc, 0x96a7b8c9daebfc0d, 0xa7b8c9daebfc0d1e,
            0xb8c9daebfc0d1e2f, 0xc9daebfc0d1e2f30, 0xdaebfc0d1e2f3041, 0xebfc0d1e2f304152,
            0xfc0d1e2f30415263, 0x0d1e2f3041526374, 0x1e2f304152637485, 0x2f30415263748596,
            0x304152637485a6b7, 0x4152637485a6b7c8, 0x52637485a6b7c8d9, 0x637485a6b7c8d9ea
        ]

        padded = self._pad_message(message)
        
        # Process each n-bit chunk
        for i in range(0, len(padded), 128):
            self._process_chunk(padded[i:i+128])

        return ''.join(f'{h:016x}' for h in self.h)
    
    def hash_with_salt(self, message, salt):
        """
        Compute SHA-6656 hash with salt (prepended to message).
        
        Args:
            message: bytes or str to hash
            salt: bytes or str salt value
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')

        salted_message = salt + message
        return self.hash(salted_message)


def sha6656(message, salt=None):
    hasher = SHA6656()
    if salt is not None:
        return hasher.hash_with_salt(message, salt)
    return hasher.hash(message)
