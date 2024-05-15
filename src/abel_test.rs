use ark_serialize::CanonicalSerialize;
use banderwagon::{Element, Fr, PrimeField};
use ffi_interface::{fr_from_le_bytes, update_commitment_sparse, Context, ZERO_POINT};
use ipa_multipoint::committer::Committer;
use rand::Rng;

const FR_SIZE: usize = 32;

pub fn check_update_bytes() {
    let a = Fr::MODULUS_BIT_SIZE;
    println!("a: {}", a);

    let zero_bytes = vec![[0 as u8; FR_SIZE]; 100];
    let old_bytes = get_random_kvs(100);
    let new_bytes = get_random_kvs(100);

    let idx: Vec<usize> = (0..100).into_iter().collect();

    let vc = Context::default();

    let origin_c = Element::zero();

    assert_eq!(origin_c.to_bytes_uncompressed(), ZERO_POINT);

    let old_c = update_commitment_sparse(
        &vc,
        origin_c.to_bytes_uncompressed(),
        idx.clone(),
        zero_bytes.clone(),
        old_bytes.clone(),
    )
    .unwrap();

    let new_c = update_commitment_sparse(
        &vc,
        origin_c.to_bytes_uncompressed(),
        idx.clone(),
        zero_bytes.clone(),
        new_bytes.clone(),
    )
    .unwrap();

    let new_c_with_delta = update_commitment_sparse(&vc, old_c, idx, old_bytes, new_bytes).unwrap();

    // let mut val_indices = vec![];
    // for i in 0..100 {
    //     val_indices.push((Fr::from_be_bytes_mod_order(&new_bytes),))
    // }
    // let test_comm = committer.commit_sparse(val_indices);

    // let new_c_with_delta =
    //     Element::from_bytes_unchecked_uncompressed(new_c_with_delta).map_to_scalar_field();
    // let new_c = Element::from_bytes_unchecked_uncompressed(new_c).map_to_scalar_field();
    // // let bytes =
    //     hex::decode("1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e1").unwrap();
    // println!("Fr order: {:?}", bytes);

    let new_c_with_delta_element = Element::from_bytes_unchecked_uncompressed(new_c_with_delta);
    let new_c_element = Element::from_bytes_unchecked_uncompressed(new_c);

    assert_eq!(new_c_with_delta_element, new_c_element, "element mismatch");
    println!("{:?}\n{:?}", new_c_with_delta_element, new_c_element);

    assert_eq!(new_c_with_delta, new_c, "bytes mismatch");

    // 结果显示，element 不同，但是相等的，但是他们的 uncompressed bytes 是不相等的.
    // a: 253
    // Element(Projective { x: BigInt([10472237914389162174, 4545001434954448698, 2216239302733925091, 5326448344336639823]), y: BigInt([11560724405961964190, 7699162942030107705, 1210320511357089051, 5730535526381752374]), t: BigInt([1837436601263535052, 7072476549734625268, 395493947656549442, 1818700385470535751]), z: BigInt([1, 0, 0, 0]) })
    // Element(Projective { x: BigInt([7974506155025422147, 1489157973583633604, 1474979595905846562, 3027068515127809529]), y: BigInt([6886019663452620131, 16781740540217526213, 2480898387282682601, 2622981333082696978]), t: BigInt([1837436601263535052, 7072476549734625268, 395493947656549442, 1818700385470535751]), z: BigInt([1, 0, 0, 0]) })
    // thread 'main' panicked at src/abel_test.rs:64:5:
    // assertion `left == right` failed: bytes mismatch
    //  left: [190, 40, 139, 26, 230, 220, 84, 145, 58, 191, 25, 130, 185, 22, 19, 63, 227, 10, 183, 88, 231, 169, 193, 30, 79, 39, 167, 102, 140, 88, 235, 73, 158, 58, 141, 139, 152, 241, 111, 160, 57, 84, 142, 99, 231, 235, 216, 106, 27, 245, 206, 175, 23, 236, 203, 16, 54, 144, 189, 22, 179, 243, 134, 79]
    //  right: [67, 215, 116, 229, 24, 35, 171, 110, 196, 156, 228, 125, 73, 141, 170, 20, 34, 205, 234, 176, 32, 46, 120, 20, 249, 85, 246, 194, 198, 78, 2, 42, 99, 197, 114, 116, 102, 14, 144, 95, 197, 7, 112, 156, 27, 184, 228, 232, 233, 226, 210, 89, 240, 235, 109, 34, 18, 237, 223, 18, 160, 179, 102, 36]
    // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
}

pub fn get_random_kvs(l: usize) -> Vec<[u8; FR_SIZE]> {
    let mut kvs = vec![];
    let mut rng = rand::thread_rng();
    (0..l).into_iter().for_each(|_| {
        let mut k: [u8; FR_SIZE] = rng.gen();
        k[31] = 0;
        kvs.push(k);
    });
    kvs
}
