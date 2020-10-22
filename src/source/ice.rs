/*
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Implementation of the ICE cipher for Rust
// http://www.darkside.com.au/ice/ice.c
// C implementation written by Written by Matthew Kwan - July 1996

use std::borrow::{BorrowMut, Borrow};

#[derive(Default)]
struct IceSubKey {
    key: [u32; 3],
}

#[derive(Default)]
struct IceKeyStruct {
    ik_size: usize,
    ik_rounds: usize,
    ik_sched: Vec<IceSubKey>
}

#[allow(non_upper_case_globals)]
const ice_smod: &'static [&'static [u32]] = &[
    &[333, 313, 505, 369],
    &[379, 375, 319, 391],
    &[361, 445, 451, 397],
    &[397, 425, 395, 505],
];

#[allow(non_upper_case_globals)]
const ice_sxor: &'static [&'static [u32]] = &[
    &[0x83, 0x85, 0x9b, 0xcd],
    &[0xcc, 0xa7, 0xad, 0x41],
    &[0x4b, 0x2e, 0xd4, 0x33],
    &[0xea, 0xcb, 0x2e, 0x04],
];

#[allow(non_upper_case_globals)]
const ice_pbox: &'static [u32] = &[
    0x00000001, 0x00000080, 0x00000400, 0x00002000,
    0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000,
    0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000,
    0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000,
    0x00040000, 0x00100000, 0x02000000, 0x80000000
];

#[allow(non_upper_case_globals)]
const ice_keyrot: &'static [i32] = &[
    0, 1, 2, 3, 2, 1, 3, 0,
    1, 3, 2, 0, 3, 1, 0, 2
];

#[allow(non_upper_case_globals)]
const ice_keyrot2: &'static [i32] = &[
    1, 3, 2, 0, 3, 1, 0, 2
];

pub struct IceEncryption {
    ice_sbox: [[u32; 1024]; 4],
    ice_key: IceKeyStruct,
}

impl IceEncryption {
    /// Create a new re-usable IceEncryption object. `n` is selected based on the desired strength
    /// of the ICE algorithm. `key` must be a slice of at least `n*8` bytes.
    ///
    /// # Arguments
    ///
    /// * `n` - The parameter `n` specifying the strength of the encryption. See algorithm for
    /// details.
    /// * `key` - An encryption key to use for this object. Must be at least `n*8` bytes in size.
    pub fn new(n: usize, key: &[u8]) -> Self {
        assert_eq!(key.len(), n*8, "Ice key must be exactly {} bytes in length for n={}", n*8, n);

        let mut obj = Self{
            ice_sbox: [[0; 1024]; 4],
            ice_key: IceEncryption::ice_key_create(n)
        };

        obj.ice_sboxes_init();

        IceEncryption::ice_key_set(obj.ice_key.borrow_mut(), key);

        return obj
    }


    /// Encrypt 8-bytes of plaintext
    ///
    /// # Arguments
    ///
    /// * `ptext` - A reference to 8-bytes of plaintext to encrypt
    /// * `ctext` - A reference to a mutable array of at least 8-bytes for ciphertext output
    pub fn encrypt(&self, ptext: &[u8], ctext: &mut [u8])
    {
        let lr = self.encrypt_block_inplace_prepare(ptext);
        self.encrypt_block_inplace(lr, ctext);
    }

   /// Prepare to encrypt 8-bytes of ciphertext in-place.
   /// Pass the return value into `encrypt_inplace` to encrypt plaintext.
   /// Using this instead of `encrypt` allows for slice reference aliasing to encrypt a buffer
   /// in-place.
   ///
   /// # Arguments
   ///
   /// * `ptext` - A reference to 8-bytes of plaintext to encrypt
   fn encrypt_block_inplace_prepare(&self, ptext: &[u8]) -> (u32, u32)
   {
        let l = ((ptext[0] as u32) << 24)
            | ((ptext[1] as u32) << 16)
            | ((ptext[2] as u32) << 8) | (ptext[3] as u32);

        let r = ((ptext[4] as u32) << 24)
            | ((ptext[5] as u32) << 16)
            | ((ptext[6] as u32) << 8) | (ptext[7] as u32);

        return (l, r)
   }

    /// Encrypt 8-bytes of plaintext in-place.
    /// Pass the return value from `encrypt_block_inplace_prepare` to encrypt plaintext.
    /// Using this instead of `encrypt` allows for slice reference aliasing to encrypt a buffer
    /// in-place.
    ///
    /// # Arguments
    ///
    /// * `lr` - The result of a call to `encrypt_block_inplace_prepare`
    fn encrypt_block_inplace(&self, lr: (u32, u32), ctext: &mut [u8])
    {
        let ik = &self.ice_key;
        let mut i: usize = 0;
        let (mut l, mut r) = lr;

            loop {
            if i >= ik.ik_rounds {
                break;
            }
            l ^= self.ice_f(r, ik.ik_sched[i].borrow());
            r ^= self.ice_f(l, ik.ik_sched[i + 1].borrow());

            i += 2;
        }

        i = 0;
        loop {
            if i >= 4 {
                break;
            }

            ctext[3 - i] = (r & 0xff) as u8;
            ctext[7 - i] = (l & 0xff) as u8;

            r >>= 8;
            l >>= 8;
            i += 1;
        }
    }

    /// Encrypt an 8-byte aligned buffer in-place.
    /// Panics if the buffer length is not divisible by 8.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer to encrypt in place.
    pub fn encrypt_buffer_inplace(&self, buffer: &mut [u8])
    {
        assert_eq!(buffer.len() % 8, 0);

        let nblocks = buffer.len() / 8;

        // decrypt each block
        for i in 0..nblocks {
            // start of this block in bytes
            let start_pos = i*8;
            // end of this block in bytes
            let end_pos = (i+1)*8;

            let lr;
            {
                // reference to the full block to decrypt
                let block = &buffer[start_pos..end_pos];
                lr = self.encrypt_block_inplace_prepare(block);
            }

            // scratch space to decrypt to
            let scratch_block = &mut buffer[start_pos..end_pos];
            self.encrypt_block_inplace(lr, scratch_block);
        }
    }


    /// Decrypt 8-bytes of ciphertext
    ///
    /// # Arguments
    ///
    /// * `ctext` - A reference to 8-bytes of ciphertext to decrypt
    /// * `ptext` - A reference to a mutable array of at least 8-bytes for plaintext output
    pub fn decrypt(&self, ctext: &[u8], ptext: &mut [u8])
    {
        let lr = self.decrypt_block_inplace_prepare(ctext);
        self.decrypt_block_inplace(lr, ptext);
    }

    /// Prepare to decrypt 8-bytes of ciphertext in-place.
    /// Pass the return value into decrypt_inplace to decrypt plaintext.
    /// Using this instead of `decrypt` allows for slice reference aliasing to decrypt a buffer
    /// in-place.
    ///
    /// # Arguments
    ///
    /// * `ctext` - A reference to 8-bytes of ciphertext to decrypt
    #[inline(always)]
    pub fn decrypt_block_inplace_prepare(&self, ctext: &[u8]) -> (u32, u32)
    {
        let l = ((ctext[0] as u32) << 24)
            | ((ctext[1] as u32) << 16)
            | ((ctext[2] as u32) << 8) | (ctext[3] as u32);

        let r = ((ctext[4] as u32) << 24)
            | ((ctext[5] as u32) << 16)
            | ((ctext[6] as u32) << 8) | (ctext[7] as u32);

        return (l, r)
    }

    /// Decrypt 8-bytes of ciphertext in-place.
    /// Pass the return value from `decrypt_block_inplace_prepare` to decrypt plaintext.
    /// Using this instead of `decrypt` allows for slice reference aliasing to decrypt a buffer
    /// in-place.
    ///
    /// # Arguments
    ///
    /// * `lr` - The result of a call to `decrypt_block_inplace_prepare`
    pub fn decrypt_block_inplace(&self, lr: (u32, u32), ptext: &mut [u8])
    {
        let ik = &self.ice_key;
        let mut i: isize;

        let (mut l, mut r) = lr;

        i = (ik.ik_rounds as isize) - 1;
        loop {
            if i <= 0 {
                break;
            }
            l ^= self.ice_f(r, ik.ik_sched[i as usize].borrow());
            r ^= self.ice_f(l, ik.ik_sched[(i - 1) as usize].borrow());

            i -= 2;
        }

        let mut i: usize = 0;
        loop {
            if i >= 4 {
                break;
            }

            ptext[3 - i] = (r & 0xff) as u8;
            ptext[7 - i] = (l & 0xff) as u8;

            r >>= 8;
            l >>= 8;
            i += 1;
        }
    }

    /// Decrypt an 8-byte aligned buffer in-place.
    /// Panics if the buffer length is not divisible by 8.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer to decrypt in place.
    pub fn decrypt_buffer_inplace(&self, buffer: &mut [u8])
    {
        assert_eq!(buffer.len() % 8, 0);

        let nblocks = buffer.len() / 8;

        // decrypt each block
        for i in 0..nblocks {
            // start of this block in bytes
            let start_pos = i*8;
            // end of this block in bytes
            let end_pos = (i+1)*8;

            let lr;
            {
                // reference to the full block to decrypt
                let block = &buffer[start_pos..end_pos];
                lr = self.decrypt_block_inplace_prepare(block);
            }

            // slice of the block to decrypt to
            let target_block = &mut buffer[start_pos..end_pos];
            self.decrypt_block_inplace(lr, target_block);
        }
    }

    fn gf_mult(mut a: u32, mut b: u32, m: u32) -> u32 {
        let mut res: u32 = 0;

        while b != 0 {
            if (b & 1) != 0 {
                res ^= a;
            }

            a <<= 1;
            b >>= 1;

            if a >= 256 {
                a ^= m;
            }
        }

        return res;
    }

    fn gf_exp7(b: u32, m: u32) -> u32 {
        let mut x: u32;

        if b == 0 {
            return 0;
        }

        x = IceEncryption::gf_mult(b, b, m);
        x = IceEncryption::gf_mult(b, x, m);
        x = IceEncryption::gf_mult(x, x, m);
        return IceEncryption::gf_mult(b, x, m);
    }

    fn ice_perm32(mut x: u32) -> u32 {
        let mut res: u32 = 0;
        let mut pbox_idx = 0;

        while x != 0 {
            if (x & 1) != 0 {
                res |= ice_pbox[pbox_idx];
            }
            pbox_idx += 1;
            x >>= 1;
        }

        return res
    }

    fn ice_sboxes_init(&mut self) {
        for i in 0..1024 {
            let col: usize = (i >> 1) & 0xff;
            let row: usize = (i & 0x1) | ((i & 0x200) >> 8);
            let mut x: u32;

            x = IceEncryption::gf_exp7((col as u32) ^ ice_sxor[0][row], ice_smod[0][row] as u32) << 24;
            self.ice_sbox[0][i] = IceEncryption::ice_perm32 (x);

            x = IceEncryption::gf_exp7((col as u32) ^ ice_sxor[1][row], ice_smod[1][row] as u32) << 16;
            self.ice_sbox[1][i] = IceEncryption::ice_perm32 (x);

            x = IceEncryption::gf_exp7((col as u32) ^ ice_sxor[2][row], ice_smod[2][row] as u32) << 8;
            self.ice_sbox[2][i] = IceEncryption::ice_perm32 (x);

            x = IceEncryption::gf_exp7((col as u32) ^ ice_sxor[3][row], ice_smod[3][row] as u32);
            self.ice_sbox[3][i] = IceEncryption::ice_perm32 (x);
        }
    }

    fn ice_key_create(n: usize) -> IceKeyStruct {
        let mut ik: IceKeyStruct = Default::default();

        if n < 1 {
            ik.ik_size = 1;
            ik.ik_rounds = 8;
        } else {
            ik.ik_size = n;
            ik.ik_rounds = n * 16;
        }

        ik.ik_sched = Vec::with_capacity(ik.ik_rounds);
        for _j in 0..ik.ik_rounds {
            ik.ik_sched.push(IceSubKey{
                key: [0; 3]
            })
        }


        return ik;
    }

    fn ice_f(&self, p: u32, sk: &IceSubKey) -> u32 {
        let tl: u32;
        let tr: u32;
        let mut al: u32;
        let mut ar: u32;

        tl = ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00);

        /* Right half expansion */
        tr = (p & 0x3ff) | ((p << 2) & 0xffc00);

        /* Perform the salt permutation */
        /* al = (tr & sk[2]) | (tl & ~sk[2]); */
        /* ar = (tl & sk[2]) | (tr & ~sk[2]); */
        al = sk.key[2] & (tl ^ tr);
        ar = al ^ tr;
        al ^= tl;

        al ^= sk.key[0];			/* XOR with the subkey */
        ar ^= sk.key[1];

        /* S-box lookup and permutation */
        return self.ice_sbox[0][(al >> 10) as usize] | self.ice_sbox[1][(al & 0x3ff) as usize]
            | self.ice_sbox[2][(ar >> 10) as usize] | self.ice_sbox[3][(ar & 0x3ff) as usize];
    }

    fn ice_key_sched_build(ik: &mut IceKeyStruct, kb: &mut [u32], n: usize, keyrot: &[i32])
    {
        for i in 0..8 {
            let kr: i32 = keyrot[i];
            let isk = &mut ik.ik_sched[n + i];

            for j in 0..3 {
                isk.key[j] = 0;
            }

            for j in 0..15 {
                let curr_sk = &mut isk.key[j % 3];

                for k in 0..4 {
                    let curr_kb = &mut kb[((kr + k) & 3) as usize];
                    let bit = *curr_kb & 1;

                    *curr_sk = (*curr_sk << 1) | bit;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    fn ice_key_set(ik: &mut IceKeyStruct, key: &[u8])
    {
        if ik.ik_rounds == 8 {
            let kb: &mut [u32] = &mut [0; 4];

            for i in 0..4 {
                kb[3 - i] = ( (key[i*2] as u32) << 8) | (key[i*2 + 1] as u32);
            }

            IceEncryption::ice_key_sched_build(ik, kb, 0, ice_keyrot);
            return;
        }

        for i in 0..ik.ik_size {
            let kb: &mut [u32] = &mut [0; 4];
            for j in 0..4 {
                kb[3 - j] = ( (key[i*8 + j*2] as u32) << 8) | (key[i*8 + j*2 + 1] as u32);
            }

            IceEncryption::ice_key_sched_build(ik, kb, i*8, ice_keyrot);
            IceEncryption::ice_key_sched_build(ik, kb, ik.ik_rounds - 8 - (i*8), ice_keyrot2);
        }
    }
}

#[test]
fn test() {
    // n=2 test
    let plaintext = "BBBBBBBB";
    let key = "AAAAAAAAAAAAAAAA";
    let mut ctext = [0; 8];
    let mut ptext = [0; 8];

    // create the key
    let state = IceEncryption::new(2, key.as_bytes());

    // encrypt the plaintext
    state.encrypt(plaintext.as_bytes(), &mut ctext);

    // ensure it's the proper ciphertext
    assert_eq!(ctext, [0xac, 0x87, 0x14, 0xe3, 0x22, 0x82, 0x56, 0x80]);

    // decrypt the plaintext
    state.decrypt(&ctext, &mut ptext);

    // ensure it matches the original plaintext
    assert_eq!(ptext, plaintext.as_bytes());

    // n = 8 test
    let key = "kFc8zALkEPTgTyDTerPjnf8LZr7aLFs9G9tDdUQFYZzffAYVnz2VzyuJ5RQwc6uH";
    let state = IceEncryption::new(8, key.as_bytes());

    state.encrypt(plaintext.as_bytes(), &mut ctext);

    assert_eq!(ctext, [0xf1, 0x75, 0x76, 0xab, 0x4a, 0x61, 0x34, 0xd7]);

    state.decrypt(&ctext, &mut ptext);

    assert_eq!(ptext, plaintext.as_bytes());
}