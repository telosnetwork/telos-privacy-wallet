use libzeropool_zkbob::POOL_PARAMS;

use libzeropool_zkbob::fawkes_crypto::rand::{thread_rng, Rng};
use libzeropool_zkbob::native::{
    note::Note,
    account::Account,
    key::{derive_key_p_d},
    cipher
};

use libzeropool_zkbob::fawkes_crypto::engines::bn256::Fr;


#[test]
fn test_encryption() {
    let mut rng = thread_rng();
    let sender_eta = rng.gen();
    let receiver_eta = rng.gen();


    let mut account: Account<Fr> = Account::sample(&mut rng, &*POOL_PARAMS);
    let mut note:Vec<Note<Fr>> = (0..2).map(|_| Note::sample(&mut rng, &*POOL_PARAMS)).collect();
    
    
    account.p_d = derive_key_p_d(account.d.as_num().clone(), sender_eta, &*POOL_PARAMS).x;
    note[0].p_d = derive_key_p_d(note[0].d.as_num().clone(), receiver_eta, &*POOL_PARAMS).x;
    

    let ciphertext = cipher::encrypt(&(0..32).map(|_| rng.gen()).collect::<Vec<_>>(), sender_eta, account, &note, &*POOL_PARAMS);

    let result_out = cipher::decrypt_out(sender_eta, &ciphertext, &*POOL_PARAMS);

    assert!(result_out.is_some(), "Could not decrypt outgoing data.");
        let (account_out, note_out) = result_out.unwrap();
        assert!(note.len()==note_out.len() && 
        note.iter().zip(note_out.iter()).all(|(l,r)| l==r) &&
        account == account_out, "Wrong outgoing data decrypted");


    let result_out = cipher::decrypt_in(receiver_eta, &ciphertext, &*POOL_PARAMS);

    assert!(result_out.len()==2 && result_out[0].is_some() && result_out[0].unwrap()==note[0] && result_out[1].is_none(), "Wrong incoming data decrypted");


}
#[test]
fn identity_recipient_encryption_is_rejected() {
    let mut rng = thread_rng();
    let account: Account<Fr> = Account::sample(&mut rng, &*POOL_PARAMS);
    let mut note: Note<Fr> = Note::sample(&mut rng, &*POOL_PARAMS);
    note.p_d = libzeropool_zkbob::fawkes_crypto::ff_uint::Num::ZERO;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cipher::encrypt(&[0u8; 32],
            libzeropool_zkbob::fawkes_crypto::ff_uint::Num::ONE,
            account, &[note], &*POOL_PARAMS)
    }));
    assert!(result.is_err());
}
