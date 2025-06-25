use rand::Rng;
use num_bigint::{BigUint, RandBigInt, RandomBits};
use num_traits::{FromPrimitive, One};

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
        DGHV {lambda, rho, eta, gamma, tau, public_key: Vec::new(), secret_key: BigUint::ZERO}
    }

    // KeyGen
    pub fn generate_keys(&mut self) {
        // Generates the key pair (sk, pk) of the scheme.

        self.secret_key = self.generate_secret_key();
        self.public_key = self.generate_public_key(&self.secret_key);
    }

    fn generate_secret_key(&self) -> BigUint {
        // Generates the secret key
        //      1. Generate a eta-bit integer p.

        let mut rng = rand::thread_rng();

        let lower_bound: BigUint = BigUint::from(2u8).pow(self.eta - 1);
        let upper_bound: BigUint = BigUint::from(2u8).pow(self.eta);

        let mut p: BigUint = rng.gen_biguint_range(&lower_bound, &upper_bound);

        if &p % BigUint::from_u8(2).unwrap() == BigUint::from_u8(0).unwrap() {
            p += BigUint::one();
        }

        p
    }

    fn generate_public_key(&self, secret_key: &BigUint) -> Vec<BigUint> {
        // Generates the public key.
        //      1. 
        
        let mut rng = rand::thread_rng();
        let mut pk: Vec<BigUint> = Vec::with_capacity(self.tau as usize);

        let q_bound: BigUint = BigUint::from(2u8).pow(self.gamma - self.eta); // TODO: check if true.
        let r_bound: BigUint = BigUint::from(2u8).pow(self.rho);

        for _i in 0..self.tau {
            let q_i: BigUint = rng.gen_biguint_below(&q_bound);
            let r_i: BigUint = rng.gen_biguint_below(&r_bound);
            let x_i: BigUint = q_i * secret_key + r_i;
            pk.push(x_i);
        }

        pk
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
