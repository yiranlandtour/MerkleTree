use sha2::Digest;
use hex;
// use rand::Rng;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

#[derive(Clone)] 
pub struct MerkleTree {
    hash: Vec<u8>,
    left: Option<Box<MerkleTree>>,
    right: Option<Box<MerkleTree>>,
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl MerkleTree {
    fn new_leaf(data: &Data) -> Self {
        MerkleTree {
            hash: hash_data(data),
            left: None,
            right: None,
        }
    }

    fn new_parent(left: MerkleTree, right: MerkleTree) -> Self {
        // println!("Hashing {:?} and {:?} = {:?}", hex::encode(&left.hash), hex::encode(&right.hash),hex::encode(hash_concat(&left.hash, &right.hash)));
        MerkleTree {
            hash: hash_concat(&left.hash, &right.hash),
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.hash.clone()
    }

    /// Constructs a Merkle tree from given input data
    fn construct(input: &[Data]) -> MerkleTree {
        let mut nodes: Vec<MerkleTree> = input.iter().map(|d| MerkleTree::new_leaf(d)).collect();

        while nodes.len() > 1 {
            let mut new_nodes = Vec::new();
            for chunk in nodes.chunks(2) {
                if chunk.len() == 2 {
                    new_nodes.push(MerkleTree::new_parent(chunk[0].clone(), chunk[1].clone()));
                } else {
                    new_nodes.push(MerkleTree::new_parent(chunk[0].clone(), chunk[0].clone()));
                }
            }
            nodes = new_nodes; 
        }
        nodes.remove(0) 
    }
    

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        let tree = MerkleTree::construct(input);
        &tree.root() == root_hash
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut hash = hash_data(data);

        for (direction, proof_hash) in &proof.hashes {
            hash = match direction {
                HashDirection::Left => hash_concat(proof_hash, &hash),
                HashDirection::Right => hash_concat(&hash, proof_hash),
            };
        }
        &hash == root_hash
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        let mut proof = Proof::default();
        if self.find_proof(data, &mut proof) {
            Some(proof)
        } else {
            None
        }
    }

    fn find_proof<'a>(&'a self, data: &Data, proof: &mut Proof<'a>) -> bool {
        if &self.hash == &hash_data(data) {
            return true;
        }

        if let Some(ref left) = self.left {
            if left.find_proof(data, proof) {
                proof.hashes.push((HashDirection::Right, &self.right.as_ref().unwrap().hash));
                return true;
            }
        }

        if let Some(ref right) = self.right {
            if right.find_proof(data, proof) {
                proof.hashes.push((HashDirection::Left, &self.left.as_ref().unwrap().hash));
                return true;
            }
        }

        false
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}



#[cfg(test)]
mod tests {
    use super::*;
    // const CHARSET: &[u8] = b"0123456789abcdef";
    
    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    //for btc transactions hashes
    // fn generate_hash_data(n:usize, length: usize) -> Vec<Data> {
    //     let mut rng = rand::thread_rng();
    //     (0..n)
    //     .map(|_| {
    //         (0..length)
    //             .map(|_| {
    //                 let idx = rng.gen_range(0..CHARSET.len());
    //                 CHARSET[idx]
    //             })
    //             .collect::<Vec<u8>>() 
    //     })
    //     .collect() // 
    // }


    #[test]
    fn test_constructions() {

        // let data1 = generate_hash_data(8,64);
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        println!("Root Hash: {:?}", hex::encode(tree.root()));
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        // Uncomment if your implementation allows for unbalanced trees
        // Hashing "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" and "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a" = "30e1867424e66e8b6d159246db94e3486778136f7e386ff5f001859d6b8484ab"
        // Hashing "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986" and "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986" = "3d14fb6d40142d70f29f15b3f6419554d61e260ae6f15929f0fd7f0f7f7ab4d1"
        // Hashing "30e1867424e66e8b6d159246db94e3486778136f7e386ff5f001859d6b8484ab" and "3d14fb6d40142d70f29f15b3f6419554d61e260ae6f15929f0fd7f0f7f7ab4d1" = "f2dcdd96791b6bac5d554f2d320e594b834f5da1981812c3707e7772234cb0ad"
        // Root Hash: "f2dcdd96791b6bac5d554f2d320e594b834f5da1981812c3707e7772234cb0ad"
        // let data = example_data(3);
        // let tree = MerkleTree::construct(&data);
        // let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        // println!("Root Hash: {:?}", hex::encode(tree.root()));
        // assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verify() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let root_hash = tree.root();
        assert!(MerkleTree::verify(&data, &root_hash));


        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let root_hash = tree.root();
        assert!(MerkleTree::verify(&data, &root_hash));
    }

    // #[test]
    // fn test_verify_proof() {
    // }

    #[test]
    fn test_prove() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let proof = tree.prove(&data[0]).expect("Proof  failed");

        // println!("Proof: {:?}", proof);
        assert!(!proof.hashes.is_empty());
        assert!(MerkleTree::verify_proof(&data[0], &proof, &tree.root()));

        
        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let proof = tree.prove(&data[3]).expect("Proof  failed");
        // println!("Proof: {:?}", proof);
        
        assert!(!proof.hashes.is_empty());
        assert!(MerkleTree::verify_proof(&data[3], &proof, &tree.root()));
    }
}