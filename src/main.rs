use std::ops::AddAssign;
use std::num::Wrapping;
use num_bigint::{ToBigInt, BigUint, BigInt};

fn main() {
    let digest = sha1("ééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé");
    println!("{:x}", digest);
}

fn sha1(m : &str) -> BigInt {
    let h0 : u32 = 0x67452301;
    let h1 : u32 = 0xEFCDAB89;
    let h2 : u32 = 0x98BADCFE;
    let h3 : u32 = 0x10325476;
    let h4 : u32 = 0xC3D2E1F0;

    //convert to bytes
    let mut bytes: Vec<u8> = m.bytes().into_iter().collect();
    let bits_len: u64 = bytes.len() as u64 * 8;

    // add 0x80 to introduce a 1 after the message
    bytes.push(1<<7);
    // padding with 0s to have a multiple of 512 bytes (counting the ending data representing the size of m in bits)
    let nbr_zero_bytes = (512 - (bits_len + 8 + 64)  % 512)/8;
    for _ in 0..nbr_zero_bytes {
        bytes.push(0);
    }
    // add the size of the message in bits, represented on 64 bits
    bytes.append(&mut cut_in_bytes(bits_len));

    // convert to chunks, which internally split data in 16 32bits-numbers and extend them to 80 32bits-numbers
    let chunks = Chunk::from_bytes(bytes);
    // initial values for sha-1
    let mut result = ResultSha1::new(h0, h1, h2, h3, h4);
    for chunk in chunks{
        result += main_operation_sha1(chunk, result.clone())
    }
    // concatenate the 5 32bits-values into a 160bits-value, this is the final digest
    result.a.0.to_bigint().unwrap() << 128 |
        result.b.0.to_bigint().unwrap() << 96 |
        result.c.0.to_bigint().unwrap() << 64 |
        result.d.0.to_bigint().unwrap() << 32 |
        result.e.0.to_bigint().unwrap()
}

#[derive(Clone)]
struct ResultSha1 {
    a:Wrapping<u32>,
    b:Wrapping<u32>,
    c:Wrapping<u32>,
    d:Wrapping<u32>,
    e:Wrapping<u32>
}

impl ResultSha1 {
    fn new(a: u32, b:u32, c:u32, d:u32, e:u32) -> ResultSha1 {
        ResultSha1{
            a: Wrapping(a),
            b: Wrapping(b),
            c: Wrapping(c),
            d: Wrapping(d),
            e: Wrapping(e)
        }
    }
}
impl AddAssign for ResultSha1 {
    fn add_assign(&mut self, rhs: Self) {
        self.a += rhs.a;
        self.b += rhs.b;
        self.c += rhs.c;
        self.d += rhs.d;
        self.e += rhs.e;
    }
}

fn main_operation_sha1(chunk: Chunk, mut r: ResultSha1) -> ResultSha1 {
    for i in 0..80 {
        let f : Wrapping<u32>;
        let k : Wrapping<u32>;
        if i <= 19 {
            f = (r.b & r.c)  | ((!r.b) & r.d);
            k = Wrapping(0x5A827999);
        }
        else if i <= 39{
            f = r.b ^ r.c ^ r.d;
            k = Wrapping(0x6ED9EBA1);
        }
        else if i <= 59 {
            f = (r.b & r.c) | (r.b & r.d) | (r.c & r.d);
            k = Wrapping(0x8F1BBCDC);
        }
        else {
            f = r.b ^ r.c ^ r.d;
            k = Wrapping(0xCA62C1D6);
        }

        let tmp = Wrapping(r.a.0.rotate_left(5)) + f + r.e + k + Wrapping(chunk.data[i]);
        r.e = r.d;
        r.d = r.c;
        r.c = Wrapping(r.b.0.rotate_left(30));
        r.b = r.a;
        r.a = tmp;
    }
    r
}

struct Chunk {
    data: [u32; 80]
}

impl Chunk {
    // convert a vector of bytes to a vector of chunks (containing 512 bytes)
    pub fn from_bytes(data: Vec<u8>) -> Vec<Chunk>{
        assert_eq!(data.len() % 64, 0);
        let mut result = Vec::new();
        // the start of every chunk of size 512 (each chunk contains 64 bytes)
        for chunk_start_idx in (0..data.len()).step_by(64) {
            let mut chunk_data = [0; 80];
            // generate the 16 words of 32 bits
            for i in 0..16 {
                // concatenate 4 bytes
                let mut concatenated_nbr: u32 = 0;
                for j in 0..3 {
                    concatenated_nbr += data[chunk_start_idx + i * 4 + j] as u32;
                    concatenated_nbr <<= 8
                }
                concatenated_nbr += data[chunk_start_idx + i * 4 + 3] as u32;
                chunk_data[i] = concatenated_nbr;
            }
            let mut chunk = Chunk { data: chunk_data };
            chunk.extend_chunk();
            result.push(chunk);
        }
        result
    }

    fn extend_chunk(&mut self) {
        for i in 16..80 {
            self.data[i] = (self.data[i-3] ^ self.data[i-8] ^ self.data[i-14] ^ self.data[i-16])
                .rotate_left(1);
        }
    }

}


// returns the 8 bits of the number in big endian
fn cut_in_bytes(mut number: u64) -> Vec<u8>{
    let mask: u64 = (1<<8) - 1;
    let mut result: Vec<u8> = Vec::with_capacity(8);
    while number != 0 {
        result.push((mask & number) as u8);
        number >>= 8;
    }
    for _ in 0..8-result.len(){
        result.push(0);
    }
    result.reverse();
    result
}

