//! Codec for the fresh WTLOS-only pool's V1 memo domain.
//!
//! This module does not activate the pool. The transaction builder must use the
//! PR7 circuit/prover source, hash the returned exact memo bytes, and sign the
//! resulting PR7 transaction hash *after* memo and pool ID are finalized.
//! Existing pool memo formats must never be passed through this codec.

pub const TAG: [u8; 4] = *b"TPD1";
pub const HEADER_LEN: usize = 28;
const COUNT_LEN: usize = 4;
const ACCOUNT_HASH_LEN: usize = 32;
const MAX_ITEMS: u32 = 128;
const MAX_MEMO_LEN: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionKind {
    Deposit,
    Transfer,
    Withdraw,
}

impl TransactionKind {
    const fn fixed_len(self) -> usize {
        match self {
            Self::Deposit | Self::Transfer => 8,
            Self::Withdraw => 36,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    ShortCiphertext,
    InvalidItemCount,
    MissingDomain,
    WrongDomainTag,
    WrongProxy,
    WrongFixedFields,
    NativeWithdrawalDisabled,
    MemoTooLong,
}

fn item_count(raw_ciphertext: &[u8]) -> Result<u32, DomainError> {
    let count = raw_ciphertext
        .get(..COUNT_LEN)
        .ok_or(DomainError::ShortCiphertext)?;
    let count = u32::from_le_bytes([count[0], count[1], count[2], count[3]]);
    if !(1..=MAX_ITEMS).contains(&count) {
        return Err(DomainError::InvalidItemCount);
    }
    Ok(count)
}

/// Add the signed proxy domain to an *undomained* V1 PR7 ciphertext.
/// The four-byte item count remains at offset zero.
pub fn add_domain(raw_ciphertext: &[u8], proxy: &[u8; 20]) -> Result<Vec<u8>, DomainError> {
    item_count(raw_ciphertext)?;
    if raw_ciphertext.len() < COUNT_LEN + ACCOUNT_HASH_LEN {
        return Err(DomainError::ShortCiphertext);
    }

    let mut result = Vec::with_capacity(raw_ciphertext.len() + HEADER_LEN - COUNT_LEN);
    result.extend_from_slice(&raw_ciphertext[..COUNT_LEN]);
    result.extend_from_slice(&TAG);
    result.extend_from_slice(proxy);
    result.extend_from_slice(&raw_ciphertext[COUNT_LEN..]);
    Ok(result)
}

/// Verify the signed proxy domain before giving a ciphertext to the legacy
/// V1 account/note parser. The returned bytes preserve the original item count.
pub fn strip_domain(
    domain_ciphertext: &[u8],
    expected_proxy: &[u8; 20],
) -> Result<Vec<u8>, DomainError> {
    if domain_ciphertext.len() < HEADER_LEN + ACCOUNT_HASH_LEN {
        return Err(DomainError::MissingDomain);
    }
    item_count(domain_ciphertext)?;
    if domain_ciphertext[COUNT_LEN..COUNT_LEN + TAG.len()] != TAG {
        return Err(DomainError::WrongDomainTag);
    }
    if domain_ciphertext[COUNT_LEN + TAG.len()..HEADER_LEN] != expected_proxy[..] {
        return Err(DomainError::WrongProxy);
    }

    let mut result = Vec::with_capacity(domain_ciphertext.len() - (HEADER_LEN - COUNT_LEN));
    result.extend_from_slice(&domain_ciphertext[..COUNT_LEN]);
    result.extend_from_slice(&domain_ciphertext[HEADER_LEN..]);
    Ok(result)
}

/// Assemble exact calldata memo bytes before computing keccak(memo) mod R.
/// A caller must pass those same bytes unchanged to the V1 relayer.
pub fn build_memo(
    kind: TransactionKind,
    fixed_fields: &[u8],
    raw_ciphertext: &[u8],
    proxy: &[u8; 20],
) -> Result<Vec<u8>, DomainError> {
    if fixed_fields.len() != kind.fixed_len() {
        return Err(DomainError::WrongFixedFields);
    }
    if kind == TransactionKind::Withdraw && fixed_fields[8..16] != [0u8; 8] {
        return Err(DomainError::NativeWithdrawalDisabled);
    }

    let domain_ciphertext = add_domain(raw_ciphertext, proxy)?;
    let total_len = fixed_fields
        .len()
        .checked_add(domain_ciphertext.len())
        .ok_or(DomainError::MemoTooLong)?;
    if total_len > MAX_MEMO_LEN {
        return Err(DomainError::MemoTooLong);
    }
    let mut memo = Vec::with_capacity(total_len);
    memo.extend_from_slice(fixed_fields);
    memo.extend_from_slice(&domain_ciphertext);
    Ok(memo)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: [u8; 20] = [0x11; 20];
    const OTHER_PROXY: [u8; 20] = [0x22; 20];

    fn ciphertext(count: u32) -> Vec<u8> {
        let mut raw = count.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0xaa; ACCOUNT_HASH_LEN]);
        raw.extend_from_slice(&[0xbb; 48]);
        raw
    }

    #[test]
    fn exact_header_and_roundtrip() {
        let raw = ciphertext(1);
        let tagged = add_domain(&raw, &PROXY).unwrap();
        assert_eq!(&tagged[..4], &[1, 0, 0, 0]);
        assert_eq!(&tagged[4..8], b"TPD1");
        assert_eq!(&tagged[8..28], &PROXY);
        assert_eq!(&tagged[28..60], &[0xaa; 32]);
        assert_eq!(strip_domain(&tagged, &PROXY).unwrap(), raw);
    }

    #[test]
    fn fee_and_withdrawal_offsets_are_unchanged() {
        let raw = ciphertext(1);
        let transfer = build_memo(
            TransactionKind::Transfer,
            &[0, 0, 0, 0, 0, 0, 0, 7],
            &raw,
            &PROXY,
        )
        .unwrap();
        assert_eq!(&transfer[..8], &[0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(
            &transfer[8..36],
            &[&[1, 0, 0, 0][..], b"TPD1", &PROXY].concat()
        );

        let mut fixed = [0u8; 36];
        fixed[7] = 7;
        fixed[16..36].fill(0xdd);
        let withdraw = build_memo(TransactionKind::Withdraw, &fixed, &raw, &PROXY).unwrap();
        assert_eq!(&withdraw[..36], &fixed);
        assert_eq!(
            &withdraw[36..64],
            &[&[1, 0, 0, 0][..], b"TPD1", &PROXY].concat()
        );
    }

    #[test]
    fn wrong_tag_and_proxy_fail_closed() {
        let mut tagged = add_domain(&ciphertext(1), &PROXY).unwrap();
        assert_eq!(
            strip_domain(&tagged, &OTHER_PROXY),
            Err(DomainError::WrongProxy)
        );
        tagged[4] ^= 1;
        assert_eq!(
            strip_domain(&tagged, &PROXY),
            Err(DomainError::WrongDomainTag)
        );
    }

    #[test]
    fn invalid_counts_fail_closed() {
        for count in [0, 129, 65_536] {
            assert_eq!(
                add_domain(&ciphertext(count), &PROXY),
                Err(DomainError::InvalidItemCount)
            );
        }
    }

    #[test]
    fn short_ciphertexts_fail_closed() {
        assert_eq!(add_domain(&[], &PROXY), Err(DomainError::ShortCiphertext));
        assert_eq!(
            add_domain(&[1, 0, 0, 0], &PROXY),
            Err(DomainError::ShortCiphertext)
        );
        assert_eq!(
            strip_domain(&[1, 0, 0, 0], &PROXY),
            Err(DomainError::MissingDomain)
        );
    }

    #[test]
    fn fixed_field_size_and_native_conversion_fail_closed() {
        let raw = ciphertext(1);
        assert_eq!(
            build_memo(TransactionKind::Transfer, &[0; 7], &raw, &PROXY),
            Err(DomainError::WrongFixedFields)
        );
        let mut fixed = [0u8; 36];
        fixed[15] = 1;
        assert_eq!(
            build_memo(TransactionKind::Withdraw, &fixed, &raw, &PROXY),
            Err(DomainError::NativeWithdrawalDisabled)
        );
    }

    #[test]
    fn two_byte_memo_length_limit_is_enforced() {
        let mut raw = ciphertext(1);
        raw.resize(65_535, 0);
        assert_eq!(
            build_memo(TransactionKind::Transfer, &[0; 8], &raw, &PROXY),
            Err(DomainError::MemoTooLong)
        );
    }
}
