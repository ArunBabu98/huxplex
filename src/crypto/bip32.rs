use bip32::{DerivationPath, XPrv};

pub fn derive_mldsa_seed(bytes: [u8; 64], index: u32) -> [u8; 32] {
    let path_str = format!("m/44'/931931'/0'/0'/{index}'");
    let path: DerivationPath = path_str.parse().expect("Invalid path string");
    let child_xprv = XPrv::derive_from_path(&bytes, &path).expect("BIP32 derivation failed");

    // 4. Extract the 32-byte private key to use as the ML-DSA entropy
    let mut mldsa_seed = [0u8; 32];
    mldsa_seed.copy_from_slice(&child_xprv.private_key().to_bytes());

    mldsa_seed
}
