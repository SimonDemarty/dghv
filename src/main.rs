use rand::Rng;
use num_bigint::{BigUint, RandBigInt, RandomBits};
use num_traits::{ConstZero, FromPrimitive, One, Pow, Zero};
use num_primes::Generator;

use std::fs::File;
use std::io::{self, Write};

pub struct DGHV {
    
    lambda: u32,    // Security parameter
    rho: u32,       // Bit length of the noise
    eta: u32,       // Bit length of secret key
    gamma: u32,     // Bit length of the x_i in public key
    tau: u32,       // Number of x_i in public key

    pub public_key: Vec<BigUint>,
    pub secret_key: BigUint,
}

impl DGHV {
    pub fn initialise(lambda: u32, rho: u32, eta: u32, gamma: u32, tau: u32) -> Self {
        // Initialises a DGHV scheme with the given parameters.
        DGHV {lambda, rho, eta, gamma, tau, public_key: Vec::new(), secret_key: BigUint::zero()}
    }

    // KeyGen
    pub fn generate_keys(&mut self) {
        // Generates the key pair (sk, pk) of the scheme.

        self.secret_key = self.generate_secret_key();
        self.public_key = self.generate_public_key(&self.secret_key);
    }

    fn generate_secret_key(&self) -> BigUint {
        // Generates the secret key
        let p = Generator::new_prime(self.eta as usize);
        p
    }

    fn generate_public_key(&self, secret_key: &BigUint) -> Vec<BigUint> {
        // Generates the public key.
        //      1. 
        
        let mut rng = rand::thread_rng();
        let mut pk: Vec<BigUint> = Vec::with_capacity(self.tau as usize);

        let q_bound: BigUint = BigUint::from(2u8).pow(self.gamma - self.eta); // TODO: check if true.
        let r_bound: BigUint = BigUint::from(2u8).pow(self.rho);

        loop {
             pk.clear();

            let mut max: BigUint = BigUint::zero();
            let mut max_i: usize = 0;
            for i in 0..self.tau {
                let q_i: BigUint = rng.gen_biguint_below(&q_bound);
                let r_i: BigUint = rng.gen_biguint_below(&r_bound);
                let x_i: BigUint = q_i * secret_key + r_i;
    
                pk.push(x_i.clone());
    
                if max < x_i {
                    max = x_i;
                    max_i = i as usize;
                }
            }

            // make sure x_0 is odd
            if &max % BigUint::from_u8(2).unwrap() == BigUint::zero() {
                max += BigUint::one();
            }

            // make sure [x_0]p is even
            let x0_modp: BigUint = &max % secret_key;
            let x0_modp_centered: BigUint;
            if x0_modp > secret_key / &BigUint::from(2u8) {
                x0_modp_centered = x0_modp - secret_key;
            } else {
                x0_modp_centered = x0_modp;
            }

            if &x0_modp_centered % BigUint::from_u8(2).unwrap() == BigUint::one() {
                pk.swap(max_i, 0);
                break;
            }
            
        }
        pk
    }

    // Encrypt & Decrypt
    pub fn encrypt(&self, message_bit: u8) -> Option<BigUint> {
        // Encrypts a message bit.
        // Returns None if the message bit is invalid.

        // 1. Validate the message bit.
        if message_bit > 1 {
            eprintln!("[ERROR]: message_bit should be 0 or 1 - not {}", message_bit);
            return None;
        }

        let mut rng = rand::thread_rng();
        let mut ciphertext = BigUint::zero();

        // TODO: check if correct.
        // Subset choice
        for x_i in &self.public_key {
            if rng.gen_bool(0.5) {
                ciphertext += x_i;
            }
        }

        // 3. Generate a small random noise 'r'.
        // r is typically chosen from [0, 2^rho) or (-2^rho, 2^rho).
        // For BigUint, we'll generate a non-negative r in [0, 2^rho).
        let r_bound = BigUint::from(2u8).pow(self.rho);
        let r = rng.gen_biguint_below(&r_bound);

        // 4. Calculate the final ciphertext: c = (sum of x_i in subset) + 2*r + message_bit
        let two = BigUint::from_u8(2).unwrap();
        let message_as_biguint = BigUint::from_u8(message_bit).unwrap();

        ciphertext += &two * r; // Add 2 * r
        ciphertext += message_as_biguint; // Add the message bit

        Some(ciphertext) // Return the calculated ciphertext
    }
}

fn main() -> io::Result<()> {

    // toy example
    let lambda: u32 = 42;
    let rho: u32 = 26;
    let eta: u32 = 988;
    let gamma: u32 = 147456;
    let tau: u32 = 158;

    let mut dghv_scheme: DGHV = DGHV::initialise(lambda, rho, eta, gamma, tau);
    dghv_scheme.generate_keys();
    println!("Secret Key: {:?}", dghv_scheme.secret_key);

    // Save public keu to file
    let public_key_filepath: &'static str = "public.key";
    let mut file: File = File::create(public_key_filepath)?;
    for (i, component) in dghv_scheme.public_key.iter().enumerate() {
        writeln!(file, "x_{}: {}", i, component)?;
    }
    Ok(())
}
