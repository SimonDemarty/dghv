use rand::Rng;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{FromPrimitive, One, Pow, Zero, ToPrimitive};
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

            // make sure [x_0]p (centered) is even
            // max is the current candidate for pk[0]
            // max itself is already ensured to be odd by prior code.
            let two = BigUint::from_u8(2).unwrap(); // Define two if not in scope, or use BigUint::from(2u8).unwrap()
            let x0_candidate_mod_p = &max % secret_key; // This is in [0, p-1]
            let p_div_2 = secret_key / &two;

            let centered_x0_parity: BigUint;
            if x0_candidate_mod_p > p_div_2 {
                // Centered value is x0_candidate_mod_p - secret_key (conceptually negative)
                // Parity is ( (x0_candidate_mod_p % 2) + (secret_key % 2) ) % 2
                // Since secret_key is an odd prime, secret_key % 2 is 1.
                // Parity is ( (x0_candidate_mod_p % 2) + 1 ) % 2
                centered_x0_parity = ( (&x0_candidate_mod_p % &two) + BigUint::one() ) % &two;
            } else {
                // Centered value is x0_candidate_mod_p (non-negative)
                // Parity is x0_candidate_mod_p % 2
                centered_x0_parity = &x0_candidate_mod_p % &two;
            }

            // The comment says "make sure [x_0]p is even".
            // So, if centered_x0_parity is zero (even), we are good.
            if centered_x0_parity == BigUint::zero() {
                pk.swap(max_i, 0); // Place the conforming 'max' at pk[0]
                break; // Condition met, exit loop.
            }
            // If centered_x0_parity is one (odd), the condition is not met.
            // The loop will continue to generate a new set of pk elements.
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

    pub fn decrypt(&self, ciphertext: BigUint) -> u8 {
        let two = BigUint::from_u8(2).unwrap();
        let p = &self.secret_key;

        let c_mod_p = &ciphertext % p; // c_mod_p is in [0, p-1]

        // Determine the message bit by considering the centered remainder
        let p_div_2 = p / &two;
        let mut m_prime = &c_mod_p % &two; // m' = (c_mod_p) mod 2

        // If c_mod_p > p/2, it means the "effective" remainder (c_mod_p - p) was negative.
        // Since p is odd, (c_mod_p - p) mod 2 flips the bit compared to (c_mod_p) mod 2.
        if c_mod_p > p_div_2 {
            m_prime = if m_prime == BigUint::zero() {
                BigUint::one()
            } else {
                BigUint::zero()
            };
        }

        m_prime.to_u8().unwrap_or_else(|| {
            eprintln!("[WARN]: Decrypted message_bit could not be converted to u8. Defaulting to 0.");
            0
        })
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
    println!("Public key saved to {}", public_key_filepath);

    // Basic Encryption/Decryption Test
    println!("\nTesting encryption and decryption...");

    let message0: u8 = 0;
    match dghv_scheme.encrypt(message0) {
        Some(ciphertext0) => {
            let decrypted0 = dghv_scheme.decrypt(ciphertext0);
            println!("Original: {}, Encrypted then Decrypted: {}", message0, decrypted0);
            assert_eq!(message0, decrypted0, "Test failed: Decrypt(Encrypt(0)) did not return 0.");
        }
        None => {
            eprintln!("Encryption of 0 returned None, test failed.");
            // Consider panicking here or returning an error from main
            return Err(io::Error::new(io::ErrorKind::Other, "Encryption of 0 failed"));
        }
    }

    let message1: u8 = 1;
    match dghv_scheme.encrypt(message1) {
        Some(ciphertext1) => {
            let decrypted1 = dghv_scheme.decrypt(ciphertext1);
            println!("Original: {}, Encrypted then Decrypted: {}", message1, decrypted1);
            assert_eq!(message1, decrypted1, "Test failed: Decrypt(Encrypt(1)) did not return 1.");
        }
        None => {
            eprintln!("Encryption of 1 returned None, test failed.");
            return Err(io::Error::new(io::ErrorKind::Other, "Encryption of 1 failed"));
        }
    }

    println!("Basic encryption and decryption tests passed!");

    Ok(())
}
