use rand::Rng;
use num_bigint::{BigUint, RandBigInt, RandomBits};
use num_traits::{ConstZero, FromPrimitive, ToPrimitive, One, Pow, Zero};
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

        self.secret_key = self.generate_secret_key();
        self.public_key = self.generate_public_key(&self.secret_key);
    }

    fn generate_secret_key(&self) -> BigUint {
        return Generator::new_prime(self.eta as usize);
    }

    fn generate_public_key(&self, secret_key: &BigUint) -> Vec<BigUint> {
       
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

        // message bit validation
        if message_bit > 1 {
            eprintln!("[ERROR]: message_bit should be 0 or 1 - not {}", message_bit);
            return None;
        }
        
        let mut rng = rand::thread_rng();
        let mut ciphertext = BigUint::zero();

        let two = BigUint::from_u8(2).unwrap();
        let message_as_biguint = BigUint::from_u8(message_bit).unwrap();
        
        let r_bound = BigUint::from(2u8).pow(self.rho);
        let r = rng.gen_biguint_below(&r_bound);

        // actual ciphertext
        for x_i in &self.public_key {
            if rng.gen_bool(0.5) {
                ciphertext += x_i;
            }
        }        

        ciphertext += &two * r;
        ciphertext += message_as_biguint;

        ciphertext = &ciphertext % &self.public_key[0];

        Some(ciphertext) // Return the calculated ciphertext
    }

    pub fn decrypt(&self, ciphertext: BigUint) -> u8 {
        let two = BigUint::from_u8(2).unwrap();

        let c_mod_p: BigUint = &ciphertext % &self.secret_key;
        let message_biguint: BigUint = &c_mod_p % &two;
        
        message_biguint.to_u8().unwrap_or_else(|| {
            eprintln!("[WARN]: Decrypted message_bit was not 0 or 1, or failed to convert to u8. Defaulting to 0.");
            0 
        })
    }
}

fn main() {

    // toy example
    // let lambda: u32 = 42;
    // let rho: u32 = 26;
    // let eta: u32 = 988;
    // let gamma: u32 = 147456;
    // let tau: u32 = 158;

    // small example
    let lambda: u32 = 52;
    let rho: u32 = 41;
    let eta: u32 = 1558;
    let gamma: u32 = 843033;
    let tau: u32 = 572;

    // medium example
    // let lambda: u32 = 62;
    // let rho: u32 = 56;
    // let eta: u32 = 2128;
    // let gamma: u32 = 4251866;
    // let tau: u32 = 2110;

    // large example
    // let lambda: u32 = 72;
    // let rho: u32 = 71;
    // let eta: u32 = 2698;
    // let gamma: u32 = 19575950;
    // let tau: u32 = 7659;

    let mut dghv_scheme: DGHV = DGHV::initialise(lambda, rho, eta, gamma, tau);
    dghv_scheme.generate_keys();

    let ct_0: Option<BigUint> = dghv_scheme.encrypt(0);
    // let ct_1: Option<BigUint> = dghv_scheme.encrypt(0);

    match ct_0 {
        Some(ref val) => {
            // println!("Encrypt(0) = {}", val);
            let m_0 = dghv_scheme.decrypt(val.clone());
            println!("Decrypt(Encrypt(0)) = {}", m_0)
        },
        None => println!("Encrypt(0) = None"),
    }
}
