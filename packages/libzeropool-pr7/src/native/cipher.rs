use crate::{
    fawkes_crypto::{
        ff_uint::{Num, seedbox::{SeedboxChaCha20, SeedBox, SeedBoxGen}},
        borsh::{BorshSerialize, BorshDeserialize},
        native::ecc::{EdwardsPoint},

    },
    native::{
        account::Account,
        note::Note,
        params::PoolParams,
        key::{derive_key_a, derive_key_p_d}
    },
    constants::{self, SHARED_SECRETS_HEAPLESS_SIZE, ACCOUNT_HEAPLESS_SIZE, NOTE_HEAPLESS_SIZE}
};

use sha3::{Digest, Keccak256};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::AeadMutInPlace};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::aead::heapless::Vec as HeaplessVec;

/// Wrapper for HeaplessVec (if buffer size is less or equals to N) or Vec otherwise
enum Buffer<T, const N: usize> {
    HeapBuffer(Vec<T>),
    HeaplessBuffer(HeaplessVec<T, N>)
}

impl<T, const N: usize> Buffer<T, N> {
    fn as_slice(&self) -> &[T] {
        match self {
            Self::HeapBuffer(vec) => vec.as_slice(),
            Self::HeaplessBuffer(heapless_vec) => heapless_vec.as_slice()
        }
    }
}

fn keccak256(data:&[u8])->[u8;constants::U256_SIZE] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut res = [0u8;constants::U256_SIZE];
    res.iter_mut().zip(hasher.finalize().into_iter()).for_each(|(l,r)| *l=r);
    res
}

//key stricly assumed to be unique for all messages. Using this function with multiple messages and one key is insecure!
fn symcipher_encode(key:&[u8], data:&[u8])->Vec<u8> {
    assert!(key.len()==constants::U256_SIZE);
    let nonce = Nonce::from_slice(&constants::ENCRYPTION_NONCE);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(nonce, data.as_ref()).unwrap()
}

/// Decrypts message in place if `ciphertext.len()` is less or equals to N, otherwise allocates memory in heap.
/// Key stricly assumed to be unique for all messages. Using this function with multiple messages and one key is insecure!
fn symcipher_decode<const N: usize>(key: &[u8], ciphertext: &[u8]) -> Option<Buffer<u8, N>> {
    assert!(key.len()==constants::U256_SIZE);
    let nonce = Nonce::from_slice(&constants::ENCRYPTION_NONCE);
    let mut cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    if ciphertext.len() <= N {
        let mut buffer = HeaplessVec::<u8, N>::from_slice(ciphertext).ok()?;
        cipher.decrypt_in_place(nonce, b"", &mut buffer).ok()?;
        Some(Buffer::HeaplessBuffer(buffer))
    } else {
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        Some(Buffer::HeapBuffer(plain))
    }
}

pub fn encrypt<P: PoolParams>(
    entropy: &[u8],
    eta:Num<P::Fr>,
    account: Account<P::Fr>,
    note: &[Note<P::Fr>],
    params:&P
) -> Vec<u8> {
    let nozero_notes_num = note.len();
    let nozero_items_num = nozero_notes_num+1;


    let mut sb = SeedboxChaCha20::new_with_salt(entropy);

    let account_data = {
        let mut account_key = [0u8;constants::U256_SIZE];
        sb.fill_bytes(&mut account_key);
        let account_ciphertext = symcipher_encode(&account_key, &account.try_to_vec().unwrap());
        (account_key, account_ciphertext)
    };
    
    
    let notes_data = note.iter().map(|e|{
        let a:Num<P::Fs> = sb.gen();
        let p_d = EdwardsPoint::subgroup_decompress(e.p_d, params.jubjub()).unwrap();
        // x=0 decompresses to the identity, yielding a public constant ECDH
        // secret for every ephemeral scalar.  Do not encrypt to that address.
        assert_ne!(p_d.x, Num::ZERO, "identity note recipient is forbidden");
        let ecdh =  p_d.mul(a, params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let ciphertext = symcipher_encode(&key, &e.try_to_vec().unwrap());
        let a_pub = derive_key_p_d(e.d.to_num(), a, params); 
        (a_pub.x, key, ciphertext)
        
    }).collect::<Vec<_>>();

    let shared_secret_data = {
        let a_p_pub = derive_key_a(sb.gen(), params);
        let ecdh = a_p_pub.mul(eta.to_other_reduced(), params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let text:Vec<u8> = core::iter::once(&account_data.0[..]).chain(notes_data.iter().map(|e| &e.1[..])).collect::<Vec<_>>().concat();
        let ciphertext = symcipher_encode(&key, &text);
        (a_p_pub.x, ciphertext)
    };

    let mut res = vec![];

    (nozero_items_num as u32).serialize(&mut res).unwrap();
    account.hash(params).serialize(&mut res).unwrap();

    for e in note.iter() {
        e.hash(params).serialize(&mut res).unwrap();
    }
    shared_secret_data.0.serialize(&mut res).unwrap();
    res.extend(&shared_secret_data.1);

    res.extend(&account_data.1);

    notes_data.iter().for_each(|nd|{
        nd.0.serialize(&mut res).unwrap();
        res.extend(&nd.2);
    });

    res
}


fn buf_take<'a>(memo: &mut &'a[u8], size:usize) -> Option<&'a[u8]> {
    if memo.len() < size {
        None
    } else {
        let res = &memo[0..size];
        *memo = &memo[size..];
        Some(res)
    }
}

pub fn decrypt_out<P: PoolParams>(eta:Num<P::Fr>, mut memo:&[u8], params:&P)->Option<(Account<P::Fr>, Vec<Note<P::Fr>>)> {
    let num_size = constants::num_size_bits::<P::Fr>()/8;
    let account_size = constants::account_size_bits::<P::Fr>()/8;
    let note_size = constants::note_size_bits::<P::Fr>()/8;


    let nozero_items_num = u32::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * constants::U256_SIZE + constants::POLY_1305_TAG_SIZE;

    let account_hash = Num::deserialize(&mut memo).ok()?;
    let note_hashes = buf_take(&mut memo, nozero_notes_num * num_size)?;

    let shared_secret_text = decrypt_ecdh::<P, SHARED_SECRETS_HEAPLESS_SIZE>(eta, &mut memo, shared_secret_ciphertext_size, params)?;

    let mut shared_secret_text_ptr = shared_secret_text.as_slice();

    let account_key= <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr).ok()?;
    let note_key = (0..nozero_notes_num).map(|_| <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr)).collect::<Result<Vec<_>,_>>().ok()?;

    let account_ciphertext = buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;
    let account = decrypt_account(&account_key, account_ciphertext, account_hash, params)?;

    let note = (0..nozero_notes_num).map(|i| {
        buf_take(&mut memo, num_size)?;
        let note_hash = {
            let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
            Num::deserialize(note_hash).ok()?
        };

        let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;

        decrypt_note(&note_key[i], ciphertext, note_hash, params)
    }).collect::<Option<Vec<_>>>()?;
    
    Some((account, note))
}

fn decrypt_ecdh<P: PoolParams, const N: usize>(eta:Num<P::Fr>, buf:&mut &[u8], size:usize, params:&P) -> Option<Buffer<u8, N>> {
    let a_p = EdwardsPoint::subgroup_decompress(Num::deserialize(buf).ok()?, params.jubjub())?;
    let ecdh = a_p.mul(eta.to_other_reduced(), params.jubjub());
    let key = {
        let mut x: [u8; 32] = [0; 32];
        ecdh.x.serialize(&mut &mut x[..]).unwrap();
        keccak256(&x)
    };
    let ciphertext = buf_take(buf, size)?;

    symcipher_decode::<N>(&key, ciphertext)
}

fn _decrypt_in<P: PoolParams>(eta:Num<P::Fr>, mut memo:&[u8], params:&P)->Option<Vec<Option<Note<P::Fr>>>> {
    let num_size = constants::num_size_bits::<P::Fr>()/8;
    let account_size = constants::account_size_bits::<P::Fr>()/8;
    let note_size = constants::note_size_bits::<P::Fr>()/8;


    let nozero_items_num = u32::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * constants::U256_SIZE + constants::POLY_1305_TAG_SIZE;

    buf_take(&mut memo, num_size)?;
    let note_hashes = buf_take(&mut memo, nozero_notes_num * num_size)?;

    buf_take(&mut memo, num_size)?;
    buf_take(&mut memo, shared_secret_ciphertext_size)?;
    buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;


    let note = (0..nozero_notes_num).map(|i| {
        let a_pub = EdwardsPoint::subgroup_decompress(Num::deserialize(&mut memo).ok()?, params.jubjub())?;
        let ecdh = a_pub.mul(eta.to_other_reduced(), params.jubjub());
        
        let key = {
            let mut x: [u8; 32] = [0; 32];
            ecdh.x.serialize(&mut &mut x[..]).unwrap();
            keccak256(&x)
        };

        let note_hash = {
            let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
            Num::deserialize(note_hash).ok()?
        };
        
        let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;

        decrypt_note(&key, ciphertext, note_hash, params)
    }).collect::<Vec<Option<_>>>();

    Some(note)
}

pub fn decrypt_in<P: PoolParams>(eta:Num<P::Fr>, memo:&[u8], params:&P)->Vec<Option<Note<P::Fr>>> {
    if let Some(res) = _decrypt_in(eta, memo, params) {
        res
    } else {
        vec![]
    }
}

/// get encrypted memo chunks with associated decryption keys (chunk: account or note)
/// returns vector of tupple (index, chunk, key)
/// indexes are zero-based and enumerated within current memo
pub fn symcipher_decryption_keys<P: PoolParams>(eta:Num<P::Fr>, mut memo:&[u8], params:&P) -> Option<Vec<(u64, Vec<u8>, Vec<u8>)>> {
    let num_size = constants::num_size_bits::<P::Fr>()/8;
    let account_size = constants::account_size_bits::<P::Fr>()/8;
    let note_size = constants::note_size_bits::<P::Fr>()/8;

    let nozero_items_num = u32::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * constants::U256_SIZE + constants::POLY_1305_TAG_SIZE;

    let account_hash = Num::deserialize(&mut memo).ok()?;
    let note_hashes = buf_take(&mut memo, nozero_notes_num * num_size)?;

    let shared_secret_text = decrypt_ecdh::<P, SHARED_SECRETS_HEAPLESS_SIZE>(eta, &mut memo, shared_secret_ciphertext_size, params);

    if let Some(shared_secret_text) = shared_secret_text {
        // here is a our transaction, we can restore account and all notes
        let mut shared_secret_text_ptr = shared_secret_text.as_slice();

        let account_key= <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr).ok()?;
        let note_key = (0..nozero_notes_num).map(|_| <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr)).collect::<Result<Vec<_>,_>>().ok()?;

        let account_ciphertext = buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;
        let _ = decrypt_account(&account_key, account_ciphertext, account_hash, params)?;

        let account_tuple = (0 as u64, account_ciphertext.to_vec(), account_key.to_vec());
        let result = Some(account_tuple)
            .into_iter()
            .chain(
                (0..nozero_notes_num).filter_map(|i| {
                buf_take(&mut memo, num_size)?;

                let note_hash = {
                    let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
                    Num::deserialize(note_hash).ok()?
                };

                let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;
                match decrypt_note(&note_key[i], ciphertext, note_hash, params) {
                    Some(_) => Some((i as u64 + 1, ciphertext.to_vec(), note_key[i].to_vec())),
                    _ => None,
                }
            })
        ).collect::<Vec<_>>();
        
        Some(result)
    } else {
        // search for incoming notes
        buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;   // skip account
        let notes = (0..nozero_notes_num).filter_map(|i| {
            let a_pub = EdwardsPoint::subgroup_decompress(Num::deserialize(&mut memo).ok()?, params.jubjub())?;
            let ecdh = a_pub.mul(eta.to_other_reduced(), params.jubjub());
            
            let key = {
                let mut x: [u8; 32] = [0; 32];
                ecdh.x.serialize(&mut &mut x[..]).unwrap();
                keccak256(&x)
            };
    
            let note_hash = {
                let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
                Num::deserialize(note_hash).ok()?
            };

            let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;
            match decrypt_note(&key, ciphertext, note_hash, params) {
                Some(_) => Some((i as u64 + 1, ciphertext.to_vec(), key.to_vec())),
                _ => None,
            }
        })
        .collect();

        Some(notes)
    }
}

pub fn decrypt_account<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], hash: Num<P::Fr>, params: &P) -> Option<Account<P::Fr>> {
    match decrypt_account_no_validate(symkey, ciphertext, params) {
        Some(acc) if acc.hash(params) == hash => Some(acc),
        _ => None,
    }
}

pub fn decrypt_account_no_validate<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], _: &P) -> Option<Account<P::Fr>> {
    let plain = symcipher_decode::<ACCOUNT_HEAPLESS_SIZE>(&symkey, ciphertext)?;
    Account::try_from_slice(plain.as_slice()).ok()
}

pub fn decrypt_note<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], hash: Num<P::Fr>, params: &P) -> Option<Note<P::Fr>> {
    match decrypt_note_no_validate(symkey, ciphertext, params) {
        Some(note) if note.hash(params) == hash => Some(note),
        _ => None,
    }
}

pub fn decrypt_note_no_validate<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], _: &P) -> Option<Note<P::Fr>> {
    let plain = symcipher_decode::<NOTE_HEAPLESS_SIZE>(&symkey, ciphertext)?;
    Note::try_from_slice(plain.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use crate::native::cipher::{symcipher_decryption_keys, decrypt_account, decrypt_note};
    use crate::native::note::Note;
    use crate::{POOL_PARAMS, native::boundednum::BoundedNum};
    use crate::native::account::Account;
    use fawkes_crypto::ff_uint::Num;
    use fawkes_crypto::{rand::Rng, engines::bn256::Fr};
    use fawkes_crypto::rand::rngs::OsRng;
    use crate::native::key::{derive_key_a, derive_key_eta, derive_key_p_d};

    use super::{symcipher_encode, symcipher_decode, encrypt, decrypt_out, decrypt_in};

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(100)]
    #[test_case(128)]
    #[test_case(1024)]
    fn test_symcipher(buf_len: usize) {
        let mut rng = OsRng::default();

        let key: [u8; 32] = rng.gen();
        let plaintext: Vec<u8> = (0..buf_len).map(|_| { rng.gen() }).collect();
        let ciphertext = symcipher_encode(&key, &plaintext.as_slice());
        let decrypted = symcipher_decode::<0>(&key, &ciphertext.as_slice()).unwrap();

        assert_eq!(plaintext.len(), decrypted.as_slice().len());
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    }

    #[test_case(0, 0.0)]
    #[test_case(1, 0.0)]
    #[test_case(1, 1.0)]
    #[test_case(5, 0.8)]
    #[test_case(15, 0.0)]
    #[test_case(15, 1.0)]
    #[test_case(20, 0.5)]
    #[test_case(30, 0.7)]
    #[test_case(42, 0.5)]
    fn test_decrypt_in_out(notes_count: u32, note_probability: f64) {
        let params = &POOL_PARAMS.clone();
        let mut rng = OsRng::default();

        // sender eta
        let eta1 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        // receciver eta
        let eta2 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);

        // output account
        let mut account: Account<Fr> = Account::sample(&mut rng, params);
        account.b = BoundedNum::new(Num::from(10000000000 as u64));
        account.e = BoundedNum::new(Num::from(12345 as u64));
        account.i = BoundedNum::new(Num::from(128 as u32));
        account.p_d = derive_key_p_d(account.d.to_num(), eta1, params).x;

        // output notes
        let mut dst_notes_num: usize = 0;
        let notes: Vec<Note<Fr>> = (0..notes_count as u64).map(|_| {
            let mut a_note = Note::sample(&mut rng, params);
            a_note.b = BoundedNum::new(Num::from(500000000 as u64));
            if rng.gen_bool(note_probability) {
                // a few notes to the receiver
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta2, params).x;
                dst_notes_num += 1;
            } else {
                // other notes are loopback
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta1, params).x;
            }
            a_note
        }).collect();

        // encrypt account and notes with the sender key
        let entropy: [u8; 32] = rng.gen();
        let mut encrypted = encrypt(&entropy, eta1, account, notes.as_slice(), params);

        // let's decrypt the memo from the receiver side and check the result
        let decrypted_in = decrypt_in(eta2, encrypted.as_mut_slice(), params);
        assert_eq!(decrypted_in.len(), notes.len());
        let in_notes: Vec<_> = decrypted_in
                .into_iter()
                .enumerate()
                .filter_map(|(i, note)| {
                    match note {
                        Some(note) => { //if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x => {
                            assert_eq!(&note, notes.get(i).unwrap());
                            Some(note)
                        }
                        _ => None,
                    }
                })
                .collect();
        assert_eq!(in_notes.len(), dst_notes_num);
        
        // decrypt the memo from the sender side and check the result
        let decrypted_out = decrypt_out(eta1, encrypted.as_mut_slice(), params);
        let decrypted_acc = decrypted_out.as_ref().unwrap().0;
        let decrypted_notes = &decrypted_out.as_ref().unwrap().1;
        assert_eq!(decrypted_acc, account);
        assert_eq!(decrypted_notes.len(), notes.len());
        (0..notes.len()).for_each(|i: usize| {
            let src = notes.get(i).unwrap();
            let recovered = decrypted_notes.get(i).unwrap();
            assert_eq!(src, recovered);
        });
    }

    #[test_case(0, 0.0)]
    #[test_case(1, 0.0)]
    #[test_case(1, 1.0)]
    #[test_case(3, 0.5)]
    #[test_case(10, 0.5)]
    #[test_case(15, 0.0)]
    #[test_case(30, 1.0)]
    #[test_case(42, 0.5)]
    fn test_compliance(notes_count: u32, note_probability: f64) {
        let params = &POOL_PARAMS.clone();
        let mut rng = OsRng::default();

        // sender eta
        let eta1 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        // receciver eta
        let eta2 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        // third-party eta
        let eta3 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);

        // output account
        let mut account: Account<Fr> = Account::sample(&mut rng, params);
        account.b = BoundedNum::new(Num::from(10000000000 as u64));
        account.e = BoundedNum::new(Num::from(12345 as u64));
        account.i = BoundedNum::new(Num::from(128 as u32));
        account.p_d = derive_key_p_d(account.d.to_num(), eta1, params).x;

        // output notes
        let mut dst_notes_num: usize = 0;
        let notes: Vec<Note<Fr>> = (0..notes_count as u64).map(|_| {
            let mut a_note = Note::sample(&mut rng, params);
            a_note.b = BoundedNum::new(Num::from(500000000 as u64));
            if rng.gen_bool(note_probability) {
                // a few notes to the receiver
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta2, params).x;
                dst_notes_num += 1;
            } else {
                // other notes are loopback
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta1, params).x;
            }
            a_note
        }).collect();

        // encrypt account and notes with the sender key
        let entropy: [u8; 32] = rng.gen();
        let encrypted = encrypt(&entropy, eta1, account, notes.as_slice(), params);

        // trying to restore chunks and associated decryption keys from the sender side
        let sender_restored = symcipher_decryption_keys(eta1, encrypted.as_slice(), params).unwrap();
        assert!(sender_restored.len() == notes.len() + 1);
        sender_restored.iter().for_each(|(index, chunk, key)| {
            if *index == 0 {
                // decrypt account
                let decrypt_acc = decrypt_account(key.as_slice(), chunk.as_slice(), account.hash(params), params).unwrap();
                assert_eq!(decrypt_acc, account);
            } else {
                // decrypt note
                let orig_note = notes.get((index - 1) as usize).unwrap();
                let decrypt_note = decrypt_note(key.as_slice(), chunk.as_slice(), orig_note.hash(params), params).unwrap();
                assert_eq!(decrypt_note, *orig_note);
            }
        });

        // trying to restore chunks and associated decryption keys from the receiver side
        let receiver_restored = symcipher_decryption_keys(eta2, encrypted.as_slice(), params).unwrap();
        assert!(receiver_restored.len() == dst_notes_num);
        receiver_restored.iter().for_each(|(index, chunk, key)| {
            assert_ne!(*index, 0); // account shouldn't be decrypted on receiver side
            // decrypt note
            let orig_note = notes.get((index - 1) as usize).unwrap();
            let decrypt_note = decrypt_note(key.as_slice(), chunk.as_slice(), orig_note.hash(params), params).unwrap();
            assert_eq!(decrypt_note, *orig_note);
        });

        // trying to restore memo from the third-party actor
        let thirdparty_restored = symcipher_decryption_keys(eta3, encrypted.as_slice(), params).unwrap();
        assert_eq!(thirdparty_restored.len(), 0);
    }
}
