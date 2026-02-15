pub struct Header {
    pub parent_hash: [u8; 32],
    pub number: u64,
    pub state_root: [u8; 32],      // merklee root of account balances
    pub extrinsics_root: [u8; 32], // merklee root of transactions
    pub timestamp: u64,
    pub digest: Vec<u8>, // consensus signatures
}

pub struct Transaction {
    pub nonce: u64, // preents replay attack, counter for sender transaction
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub value: u128, // hux coins
    pub gas_limit: u64,
    pub gas_price: u128,
    pub data: Vec<u8>,      // Wasm code or function calls
    pub signature: Vec<u8>, // PQ signature (~ 2420 bytes)
}

pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
    pub total_weight: u64, // Calculated size
}
