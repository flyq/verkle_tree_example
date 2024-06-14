use verkle_trie::{
    config::DefaultConfig,
    database::{memory_db::MemoryDb, ReadOnlyHigherDb},
    proof::{prover, verifier, VerkleProof},
    trie::Trie,
    Fr, TrieTrait,
};

pub fn basic_proof() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let mut keys = Vec::new();
    let mut values = Vec::new();
    let kv = kv_pair();
    for i in kv {
        keys.push(i.0);
        values.push(Some(i.1));
        trie.insert_single(i.0, i.1);
    }
    println!("trie: {:?}", trie.storage);
    // println!("poly: {:?}", trie.committer);

    let root = vec![];
    let meta = trie.storage.get_branch_meta(&root).unwrap();

    let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

    println!("proof: {:?}", proof);

    let (ok, _) = proof.check(keys, values, meta.commitment);
    assert!(ok);
}

pub fn proof_of_absence_edge_case() {
    let db = MemoryDb::new();
    let trie = Trie::new(DefaultConfig::new(db));

    let absent_keys = vec![[3; 32]];
    let absent_values = vec![None];

    let root = vec![];
    let meta = trie.storage.get_branch_meta(&root).unwrap();

    let proof = prover::create_verkle_proof(&trie.storage, absent_keys.clone()).unwrap();

    let (ok, _) = proof.check(absent_keys, absent_values, meta.commitment);
    assert!(ok);
}

pub fn prover_queries_match_verifier_queries() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let mut keys = Vec::new();
    for i in 0..=3 {
        let mut key_0 = [0u8; 32];
        key_0[0] = i;
        keys.push(key_0);
        trie.insert_single(key_0, key_0);
    }
    let root = vec![];
    let meta = trie.storage.get_branch_meta(&root).unwrap();

    let (pq, _) = prover::create_prover_queries(&trie.storage, keys.clone());
    let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

    let values: Vec<_> = keys.iter().map(|val| Some(*val)).collect();
    let (vq, _) = verifier::create_verifier_queries(proof, keys, values, meta.commitment).unwrap();

    for (p, v) in pq.into_iter().zip(vq) {
        assert_eq!(p.commitment, v.commitment);
        assert_eq!(Fr::from(p.point as u128), v.point);
        assert_eq!(p.result, v.result);
    }
}

pub fn simple_serialization_consistency() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let mut keys = Vec::new();
    for i in 0..=3 {
        let mut key_0 = [0u8; 32];
        key_0[0] = i;
        keys.push(key_0);
        trie.insert_single(key_0, key_0);
    }
    let root = vec![];
    let _meta = trie.storage.get_branch_meta(&root).unwrap();

    let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

    let mut bytes = Vec::new();
    proof.write(&mut bytes).unwrap();
    let deserialized_proof = VerkleProof::read(&bytes[..]).unwrap();
    assert_eq!(proof, deserialized_proof);
}

pub fn proof_of_absence_edge_case2() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));
    let root = vec![];

    let meta0 = trie.storage.get_branch_meta(&root).unwrap();
    println!("root commitment: {:?}", meta0.commitment);

    let keys = vec![[0; 32]];
    let values = vec![Some([0; 32])];

    trie.insert_single([0; 32], [0; 32]);

    let meta1 = trie.storage.get_branch_meta(&root).unwrap();
    println!("root commitment: {:?}", meta1.commitment);

    let mut key = [0; 32];
    key[31] = 0xff;

    trie.insert_single(key, [0; 32]);
    let meta2 = trie.storage.get_branch_meta(&root).unwrap();

    println!("root commitment: {:?}", meta2.commitment);

    let child = trie.storage.get_stem_children([0u8; 31]);
    println!("{:?}", child);

    assert_ne!(meta1.commitment, meta2.commitment);

    let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

    // println!("{:?}", proof);

    let (ok, _) = proof.check(keys, values, meta2.commitment);
    assert!(ok);

    let keys = vec![[1; 32]];
    let values = vec![None];

    let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

    // println!("new: {:?}", proof);

    let (ok, _) = proof.check(keys, values, meta2.commitment);

    assert!(ok);
}

fn kv_pair() -> Vec<([u8; 32], [u8; 32])> {
    let mut res = Vec::new();
    for i in 0..3 {
        let mut key = [0u8; 32];
        let mut value = [0u8; 32];
        key[31] = 0xff - i as u8;
        value[0] = 0xff - i as u8;
        res.push((key, value))
    }
    res
}
