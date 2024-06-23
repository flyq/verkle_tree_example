use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::committer::Committer;
use verkle_trie::constants::TWO_POW_128;
use verkle_trie::database::ReadOnlyHigherDb;
use verkle_trie::group_to_field;

pub mod abel_test;
pub mod proof;
pub mod trie;

fn main() {
    proof::basic_proof();
    // trie::test_hash()
    // proof::proof_of_absence_edge_case2();
}

// fn main() {
//     // proof::basic_proof();
//     let old_trie = trie::simple_insert();
//     // proof_of_absence_edge_case();
//     // prover_queries_match_verifier_queries();
//     // simple_serialization_consistency();
//     let low_32 =
//         Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
//     let high_32 = Fr::from_le_bytes_mod_order(&[
//         17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//     ]);

//     let low_127 =
//         Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
//     let high_127 = Fr::from_le_bytes_mod_order(&[
//         17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0x7f,
//     ]);

//     let mut evaluations = vec![Fr::from(0u32); 256];
//     evaluations[32 * 2] = low_32 + TWO_POW_128;
//     evaluations[32 * 2 + 1] = high_32;

//     evaluations[127 * 2] = low_127 + TWO_POW_128;
//     evaluations[127 * 2 + 1] = high_127;

//     let c_1 = old_trie.committer.commit_lagrange(&evaluations);
//     let h_c_1 = group_to_field(&c_1);

//     let stem_key = [
//         1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
//         26, 27, 28, 29, 30, 31,
//     ];
//     let h_c_2 = old_trie.storage.get_stem_meta(stem_key).unwrap().hash_c2;

//     // stem_commit = 1 * G[0] + stem_path * G[1] + hash(c_1) * G[2] + hash(c_2) * G[3]
//     let new_stem_commit = old_trie.committer.commit_sparse(vec![
//         (Fr::from(1u32), 0),
//         (
//             Fr::from_le_bytes_mod_order(&[
//                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
//                 24, 25, 26, 27, 28, 29, 30, 31,
//             ]),
//             1,
//         ),
//         (h_c_1, 2),
//         (h_c_2, 3),
//     ]);
//     let new_stem_hash = group_to_field(&new_stem_commit);

//     println!(
//         "New stem commitment: {:?}",
//         hex::encode(compress_point_to_array(&new_stem_commit).unwrap())
//     );
//     println!(
//         "New stem hash: {:?}",
//         hex::encode(scalar_to_array(&new_stem_hash).unwrap())
//     );
//     println!(
//         "new c_1 commitment: {:?}",
//         hex::encode(compress_point_to_array(&c_1).unwrap())
//     );
//     println!(
//         "new c_1 hash: {:?}",
//         hex::encode(scalar_to_array(&h_c_1).unwrap())
//     );

//     let stem_key_ff = [
//         1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
//         26, 27, 28, 29, 30, 0xff,
//     ];

//     let branch_id = stem_key[0..30].to_vec();

//     let h_stem_ff = old_trie
//         .storage
//         .get_stem_meta(stem_key_ff)
//         .unwrap()
//         .hash_stem_commitment;

//     let h_stem_32 = old_trie
//         .storage
//         .get_stem_meta(stem_key)
//         .unwrap()
//         .hash_stem_commitment;

//     let branch_commit = old_trie
//         .committer
//         .commit_sparse(vec![(h_stem_32, 31), (h_stem_ff, 0xff)]);
//     let branch_hash = group_to_field(&branch_commit);

//     let get_branch = old_trie.storage.get_branch_meta(&branch_id).unwrap();
//     println!(
//         "New branch commitment: {:?}",
//         hex::encode(compress_point_to_array(&branch_commit).unwrap())
//     );
//     println!(
//         "New branch hash: {:?}",
//         hex::encode(scalar_to_array(&branch_hash).unwrap())
//     );
//     println!("branch meta: {:?}", get_branch);
//     assert_eq!(branch_commit, get_branch.commitment);

//     abel_test::check_update_bytes();
// }

fn scalar_to_array(scalar: &Fr) -> Result<[u8; 32], SerializationError> {
    let mut bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut bytes[..])?;

    Ok(bytes)
}

fn compress_point_to_array(p: &Element) -> Result<[u8; 32], SerializationError> {
    let mut bytes = [0u8; 32];
    p.serialize_compressed(&mut bytes[..])?;

    Ok(bytes)
}
