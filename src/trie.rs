use banderwagon::{trait_defs::*, Element, Fr};
use ipa_multipoint::committer::DefaultCommitter;
use sha3::{Digest, Keccak256};
use std::ops::Mul;
use verkle_trie::{
    constants::{CRS, TWO_POW_128},
    database::memory_db::MemoryDb,
    database::ReadOnlyHigherDb,
    group_to_field,
    trie::paths_from_relative,
    trie::Trie,
    DefaultConfig, TrieTrait,
};

// Inserting where the key and value are all zeros
// The zeroes cancel out a lot of components, so this is a general fuzz test
// and hopefully the easiest to pass
pub fn insert_key0value0() {
    let db = MemoryDb::new();

    let mut trie = Trie::new(DefaultConfig::new(db));

    let key = [0u8; 32];
    let stem: [u8; 31] = key[0..31].try_into().unwrap();

    let ins = trie.create_insert_instructions(key, key);
    trie.process_instructions(ins);

    println!("trie: {:?}", trie.storage);
    // Value at that leaf should be zero
    assert_eq!(trie.storage.get_leaf(key).unwrap(), key);

    // There should be one stem child at index 0 which should hold the value of 0
    let mut stem_children = trie.storage.get_stem_children(stem);
    assert_eq!(stem_children.len(), 1);

    let (stem_index, leaf_value) = stem_children.pop().unwrap();
    assert_eq!(stem_index, 0);
    assert_eq!(leaf_value, key);

    // Checking correctness of the stem commitments and hashes
    let stem_meta = trie.storage.get_stem_meta(stem).unwrap();

    // C1 = (value_low + 2^128) * G0 + value_high * G1
    let value_low = Fr::from_le_bytes_mod_order(&[0u8; 16]) + TWO_POW_128;

    let c_1 = CRS[0].mul(value_low);
    assert_eq!(c_1, stem_meta.c_1);
    assert_eq!(group_to_field(&c_1), stem_meta.hash_c1);

    // c_2 is not being used so it is the identity point
    let c_2 = Element::zero();
    assert_eq!(stem_meta.c_2, c_2);
    assert_eq!(group_to_field(&c_2), stem_meta.hash_c2);

    // The stem commitment is: 1 * G_0 + stem * G_1 + group_to_field(C1) * G_2 + group_to_field(C2) * G_3
    let stem_comm_0 = CRS[0];
    let stem_comm_1 = CRS[1].mul(Fr::from_le_bytes_mod_order(&stem));
    let stem_comm_2 = CRS[2].mul(group_to_field(&c_1));
    let stem_comm_3 = CRS[3].mul(group_to_field(&c_2));
    let stem_comm = stem_comm_0 + stem_comm_1 + stem_comm_2 + stem_comm_3;
    assert_eq!(stem_meta.stem_commitment, stem_comm);

    // Root is computed as the hash of the stem_commitment * G_0
    // G_0 since the stem is situated at the first index in the child
    let hash_stem_comm = group_to_field(&stem_meta.stem_commitment);
    let root_comm = CRS[0].mul(hash_stem_comm);
    let root = group_to_field(&root_comm);

    assert_eq!(root, trie.root_hash())
}

// Test when the key is 1 to 32
pub fn insert_key1_val1() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let stem: [u8; 31] = key[0..31].try_into().unwrap();

    let ins = trie.create_insert_instructions(key, key);
    trie.process_instructions(ins);

    println!("trie: {:?}", trie.storage);

    // Value at that leaf should be [1,32]
    assert_eq!(trie.storage.get_leaf(key).unwrap(), key);

    // There should be one stem child at index 32 which should hold the value of [1,32]
    let mut stem_children = trie.storage.get_stem_children(stem);
    assert_eq!(stem_children.len(), 1);

    let (stem_index, leaf_value) = stem_children.pop().unwrap();
    assert_eq!(stem_index, 32);
    assert_eq!(leaf_value, key);

    // Checking correctness of the stem commitments and hashes
    let stem_meta = trie.storage.get_stem_meta(stem).unwrap();

    // C1 = (value_low + 2^128) * G_64 + value_high * G_65
    let value_low =
        Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
            + TWO_POW_128;
    let value_high = Fr::from_le_bytes_mod_order(&[
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ]);

    let c_1 = CRS[64].mul(value_low) + CRS[65].mul(value_high);

    assert_eq!(c_1, stem_meta.c_1);
    assert_eq!(group_to_field(&c_1), stem_meta.hash_c1);

    // c_2 is not being used so it is the identity point
    let c_2 = Element::zero();
    assert_eq!(stem_meta.c_2, c_2);
    assert_eq!(group_to_field(&c_2), stem_meta.hash_c2);

    // The stem commitment is: 1 * G_0 + stem * G_1 + group_to_field(C1) * G_2 + group_to_field(C2) * G_3
    let stem_comm_0 = CRS[0];
    let stem_comm_1 = CRS[1].mul(Fr::from_le_bytes_mod_order(&stem));
    let stem_comm_2 = CRS[2].mul(group_to_field(&c_1));
    let stem_comm_3 = CRS[3].mul(group_to_field(&c_2));
    let stem_comm = stem_comm_0 + stem_comm_1 + stem_comm_2 + stem_comm_3;
    assert_eq!(stem_meta.stem_commitment, stem_comm);

    // Root is computed as the hash of the stem_commitment * G_1
    // G_1 since the stem is situated at the second index in the child (key starts with 1)
    let hash_stem_comm = group_to_field(&stem_meta.stem_commitment);
    let root_comm = CRS[1].mul(hash_stem_comm);
    let root = group_to_field(&root_comm);

    assert_eq!(root, trie.root_hash());
    println!("root: {:?}", root.0.to_string());
}

// Test when we insert two leaves under the same stem
pub fn insert_same_stem_two_leaves() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key_a = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let stem_a: [u8; 31] = key_a[0..31].try_into().unwrap();
    let key_b = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 128, 32,
    ];
    let stem_b: [u8; 31] = key_b[0..31].try_into().unwrap();
    // assert_eq!(stem_a, stem_b);
    let stem = stem_a;

    let ins = trie.create_insert_instructions(key_a, key_a);
    trie.process_instructions(ins);

    println!("trie: {:?}\n", trie.storage);

    let ins = trie.create_insert_instructions(key_b, key_b);
    trie.process_instructions(ins);

    println!("trie: {:?}", trie.storage);

    // Fetch both leaves to ensure they have been inserted
    assert_eq!(trie.storage.get_leaf(key_a).unwrap(), key_a);
    assert_eq!(trie.storage.get_leaf(key_b).unwrap(), key_b);

    // There should be two stem children, one at index 32 and the other at index 128
    let stem_children = trie.storage.get_stem_children(stem);
    assert_eq!(stem_children.len(), 2);

    for (stem_index, leaf_value) in stem_children {
        if stem_index == 32 {
            assert_eq!(leaf_value, key_a);
        } else if stem_index == 128 {
            assert_eq!(leaf_value, key_b);
        } else {
            panic!("unexpected stem index {}", stem_index)
        }
    }

    // Checking correctness of the stem commitments and hashes
    let stem_meta = trie.storage.get_stem_meta(stem).unwrap();

    // C1 = (value_low + 2^128) * G_64 + value_high * G_65
    let value_low =
        Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
            + TWO_POW_128;
    let value_high = Fr::from_le_bytes_mod_order(&[
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ]);

    let c_1 = CRS[64].mul(value_low) + CRS[65].mul(value_high);

    assert_eq!(c_1, stem_meta.c_1);
    assert_eq!(group_to_field(&c_1), stem_meta.hash_c1);

    // C2 = (value_low + 2^128) * G_0 + value_high * G_1
    let value_low =
        Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
            + TWO_POW_128;
    let value_high = Fr::from_le_bytes_mod_order(&[
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 128,
    ]);

    let c_2 = CRS[0].mul(value_low) + CRS[1].mul(value_high);

    assert_eq!(stem_meta.c_2, c_2);
    assert_eq!(group_to_field(&c_2), stem_meta.hash_c2);

    // The stem commitment is: 1 * G_0 + stem * G_1 + group_to_field(C1) * G_2 + group_to_field(C2) * G_3
    let stem_comm_0 = CRS[0];
    let stem_comm_1 = CRS[1].mul(Fr::from_le_bytes_mod_order(&stem));
    let stem_comm_2 = CRS[2].mul(group_to_field(&c_1));
    let stem_comm_3 = CRS[3].mul(group_to_field(&c_2));
    let stem_comm = stem_comm_0 + stem_comm_1 + stem_comm_2 + stem_comm_3;
    assert_eq!(stem_meta.stem_commitment, stem_comm);

    // Root is computed as the hash of the stem_commitment * G_1
    let hash_stem_comm = group_to_field(&stem_meta.stem_commitment);
    let root_comm = CRS[1].mul(hash_stem_comm);
    let root = group_to_field(&root_comm);

    assert_eq!(root, trie.root_hash())
}

// Test where we insert two leaves, which correspond to two stems
// TODO: Is this manual test needed, or can we add it as a consistency test?
pub fn insert_key1_val1_key2_val2() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key_a = [0u8; 32];
    let stem_a: [u8; 31] = key_a[0..31].try_into().unwrap();
    let key_b = [1u8; 32];
    let stem_b: [u8; 31] = key_b[0..31].try_into().unwrap();

    let ins = trie.create_insert_instructions(key_a, key_a);
    trie.process_instructions(ins);
    let ins = trie.create_insert_instructions(key_b, key_b);
    trie.process_instructions(ins);

    let a_meta = trie.storage.get_stem_meta(stem_a).unwrap();
    let b_meta = trie.storage.get_stem_meta(stem_b).unwrap();

    let root_comm =
        CRS[0].mul(a_meta.hash_stem_commitment) + CRS[1].mul(b_meta.hash_stem_commitment);

    let expected_root = group_to_field(&root_comm);
    let got_root = trie.root_hash();
    assert_eq!(expected_root, got_root);
}

// Test where keys create the longest path
pub fn insert_longest_path() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key_a = [0u8; 32];
    let mut key_b = [0u8; 32];
    key_b[29] = 1;

    trie.insert_single(key_a, key_a);
    trie.insert_single(key_b, key_b);

    println!("trie: {:?}", trie.storage);

    let mut byts = [0u8; 32];
    trie.root_hash()
        .serialize_compressed(&mut byts[..])
        .unwrap();
    assert_eq!(
        hex::encode(byts),
        "fe2e17833b90719eddcad493c352ccd491730643ecee39060c7c1fff5fcc621a"
    );
}

// Test where keys create the longest path and the new key traverses that path
pub fn insert_and_traverse_longest_path() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key_a = [0u8; 32];
    let ins = trie.create_insert_instructions(key_a, key_a);
    trie.process_instructions(ins);

    let mut key_b = [0u8; 32];
    key_b[30] = 1;

    let ins = trie.create_insert_instructions(key_b, key_b);
    trie.process_instructions(ins);
    // Since those inner nodes were already created with key_b
    // The insertion algorithm will traverse these inner nodes
    // and later signal an update is needed, once it is inserted
    let mut key_c = [0u8; 32];
    key_c[29] = 1;

    let ins = trie.create_insert_instructions(key_c, key_c);
    trie.process_instructions(ins);

    let mut byts = [0u8; 32];
    trie.root_hash()
        .serialize_compressed(&mut byts[..])
        .unwrap();
    assert_eq!(
        hex::encode(byts),
        "74ff8821eca20188de49340124f249dac94404efdb3838bb6b4d298e483cc20e"
    );
}

pub fn empty_trie() {
    // An empty tree should return zero as the root

    let db = MemoryDb::new();
    let trie = Trie::new(DefaultConfig::new(db));

    assert_eq!(trie.root_hash(), Fr::zero())
}

pub fn simple_insert() -> Trie<MemoryDb, DefaultCommitter> {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key1 = [
        0, 147, 89, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let key2 = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    let key3 = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 0xff,
    ];
    let key4 = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 0xff, 32,
    ];
    let key5 = [
        0xff, 0xff, 0xff, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];

    trie.insert_single(key1, key1);
    trie.insert_single(key2, key2);
    trie.insert_single(key3, key3);
    trie.insert_single(key4, key4);
    trie.insert_single(key5, key5);

    println!("old trie: {:?}", trie.storage);

    let old_trie = trie.clone();
    let key6 = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 0x7f,
    ];
    trie.insert_single(key6, key6);

    println!("new trie: {:?}", trie.storage);

    old_trie
}

pub fn simple_update() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let key_a = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    trie.insert_single(key_a, [0u8; 32]);
    println!("trie: {:?}", trie.storage);

    trie.insert_single(key_a, key_a);
    println!("trie: {:?}", trie.storage);

    let mut byts = [0u8; 32];
    let root = trie.root_hash();
    root.serialize_compressed(&mut byts[..]).unwrap();

    assert_eq!(
        "029b6c4c8af9001f0ac76472766c6579f41eec84a73898da06eb97ebdab80a09",
        hex::encode(byts)
    )
}

pub fn simple_rel_paths() {
    let parent = vec![0, 1, 2];
    let rel = vec![5, 6, 7];
    let expected = vec![
        vec![0, 1, 2, 5],
        vec![0, 1, 2, 5, 6],
        vec![0, 1, 2, 5, 6, 7],
    ];
    let result = paths_from_relative(parent, rel);

    assert_eq!(result.len(), expected.len());
    for (got, expected) in result.into_iter().zip(expected) {
        assert_eq!(got, expected)
    }
}

pub fn insert_get() {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));

    let tree_key_version: [u8; 32] = [
        121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197, 120,
        243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 0,
    ];

    let tree_key_balance: [u8; 32] = [
        121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197, 120,
        243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 1,
    ];

    let tree_key_nonce: [u8; 32] = [
        121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197, 120,
        243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 2,
    ];

    let tree_key_code_keccak: [u8; 32] = [
        121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197, 120,
        243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 3,
    ];

    let tree_key_code_size: [u8; 32] = [
        121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197, 120,
        243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 4,
    ];

    let empty_code_hash_value: [u8; 32] = [
        197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83,
        202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
    ];

    let value_0: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let value_2: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ];

    trie.insert_single(tree_key_version, value_0);
    trie.insert_single(tree_key_balance, value_2);
    trie.insert_single(tree_key_nonce, value_0);
    trie.insert_single(tree_key_code_keccak, empty_code_hash_value);
    trie.insert_single(tree_key_code_size, value_0);
    println!("trie: {:?}", trie.storage);

    let _val = trie.get(tree_key_version).unwrap();
    let _val = trie.get(tree_key_balance).unwrap();
    let _val = trie.get(tree_key_nonce).unwrap();
    let _val = trie.get(tree_key_code_keccak).unwrap();
    let _val = trie.get(tree_key_code_size).unwrap();
}

pub fn test_hash() {
    for i in 0..1000u32 {
        let hash = Keccak256::digest(&i.to_le_bytes());
        let fr = Fr::from_le_bytes_mod_order(hash.as_slice());
        println!("{}", fr);
    }
}
