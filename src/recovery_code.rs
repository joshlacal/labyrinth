//! Recovery codes (SPEC §6.1, paper p.30–32, [CB-12]).
//!
//! A recovery code is 40 characters over the alphabet
//! `ACDEFHJKLMNPQRSTUVWXYZ0123456789`: a version (`2` or `3`), identifier
//! `0`, 34 entropy characters and 4 ECC characters. Version `3` codes need
//! an erasable share as well ([`crate::recovery_share`]). The ECC is a GF(32) erasure
//! code whose parity-check matrix has every three columns independent, so up
//! to three wrong characters (outside the version/identifier) can be
//! corrected by brute force: [`RecoveryCode::candidates`] yields every
//! codeword within three substitutions, and the caller keeps the one whose
//! derived `vdeviceId` exists on the backend.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

/// The 32-character alphabet; a symbol's value is its index here.
pub const ALPHABET: &[u8; 32] = b"ACDEFHJKLMNPQRSTUVWXYZ0123456789";
/// Total length of a recovery code in characters.
pub const CODE_LEN: usize = 40;
/// Number of entropy characters.
pub const ENTROPY_LEN: usize = 34;
/// Number of ECC characters.
pub const ECC_LEN: usize = 4;
/// The version-2 character (the code alone opens the bundle).
pub const VERSION: u8 = b'2';
/// The version-3 character (the code plus an erasable share open the bundle).
pub const VERSION_V3: u8 = b'3';
/// The only supported identifier character.
pub const IDENTIFIER: u8 = b'0';
/// The most erasures [`RecoveryCode::candidates`] tries.
pub const MAX_CORRECTIONS: usize = 3;

/// Length of the protected word (entropy || ecc).
const WORD_LEN: usize = ENTROPY_LEN + ECC_LEN;

// ---------------------------------------------------------------------------
// GF(32) = GF(2)[x] / (x^5 + x^2 + 1)
// ---------------------------------------------------------------------------

mod gf {
    /// Reduction polynomial x^5 + x^2 + 1.
    const POLY: u8 = 0b10_0101;

    const fn tables() -> ([u8; 62], [u8; 32]) {
        let mut exp = [0u8; 62];
        let mut log = [0u8; 32];
        let mut x: u8 = 1;
        let mut i = 0;
        while i < 31 {
            exp[i] = x;
            exp[i + 31] = x;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x20 != 0 {
                x ^= POLY;
            }
            i += 1;
        }
        (exp, log)
    }

    const TABLES: ([u8; 62], [u8; 32]) = tables();
    const EXP: [u8; 62] = TABLES.0;
    const LOG: [u8; 32] = TABLES.1;

    #[inline]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
        }
    }

    /// Multiplicative inverse; `a` must be non-zero.
    #[inline]
    pub fn inv(a: u8) -> u8 {
        debug_assert!(a != 0);
        EXP[(31 - LOG[a as usize] as usize) % 31]
    }
}

/// The 4×38 parity-check matrix `G` (SPEC §6.1 [CB-12]), stored by column.
///
/// Column `k` is `(1, N(γ^k), a_k, b_k)` where `γ^k = a_k + b_k·ω` in
/// GF(1024) = GF(32)\[ω\], `ω² + ω + 1 = 0`, `γ = 6 + ω`, and
/// `N(a + bω) = a² + ab + b²`. These are 38 points of an elliptic quadric in
/// PG(3,32), so any three columns are independent. Columns 34..37 (the ECC
/// positions) are independent too. `tests::matrix_matches_rule` regenerates
/// this table from the rule.
const H: [[u8; 4]; WORD_LEN] = {
    const R0: [u8; WORD_LEN] = [1; WORD_LEN];
    const R1: [u8; WORD_LEN] = [
        1, 19, 8, 12, 10, 15, 26, 23, 14, 9, 31, 2, 3, 16, 24, 20, 30, 17, 11, 28, 18, 27, 4, 6, 5,
        21, 13, 25, 7, 22, 29, 1, 19, 8, 12, 10, 15, 26,
    ];
    const R2: [u8; WORD_LEN] = [
        1, 6, 21, 16, 29, 5, 4, 17, 23, 28, 18, 0, 27, 27, 31, 27, 25, 29, 26, 27, 12, 8, 2, 14,
        13, 4, 29, 27, 26, 30, 9, 24, 7, 19, 5, 13, 24, 1,
    ];
    const R3: [u8; WORD_LEN] = [
        0, 1, 1, 18, 1, 26, 9, 30, 1, 16, 3, 27, 11, 15, 19, 9, 1, 30, 13, 28, 5, 23, 2, 12, 15, 5,
        31, 10, 8, 7, 11, 29, 1, 0, 19, 19, 27, 19,
    ];
    let mut cols = [[0u8; 4]; WORD_LEN];
    let mut j = 0;
    while j < WORD_LEN {
        cols[j] = [R0[j], R1[j], R2[j], R3[j]];
        j += 1;
    }
    cols
};

/// `G · word` over GF(32).
fn syndrome(word: &[u8; WORD_LEN]) -> [u8; 4] {
    let mut s = [0u8; 4];
    for (col, &w) in H.iter().zip(word.iter()) {
        for (si, &h) in s.iter_mut().zip(col.iter()) {
            *si ^= gf::mul(h, w);
        }
    }
    s
}

/// Solve `[G_S] e = s` for the columns `cols` (k ≤ 4 columns), using all
/// four equations. Returns `None` if the system is inconsistent. Columns
/// must be linearly independent (true for any ≤3 columns of `G`, and for the
/// ECC columns), which makes the solution unique when it exists.
fn solve(cols: &[usize], s: [u8; 4]) -> Option<[u8; 4]> {
    let k = cols.len();
    debug_assert!(k <= 4);
    // Augmented 4×(k+1) matrix, stored as rows.
    let mut m = [[0u8; 5]; 4];
    for (r, row) in m.iter_mut().enumerate() {
        for (c, &col) in cols.iter().enumerate() {
            row[c] = H[col][r];
        }
        row[k] = s[r];
    }
    for c in 0..k {
        let p = (c..4).find(|&r| m[r][c] != 0)?;
        m.swap(c, p);
        let iv = gf::inv(m[c][c]);
        for v in m[c].iter_mut().take(k + 1) {
            *v = gf::mul(*v, iv);
        }
        let pivot = m[c];
        for (r, row) in m.iter_mut().enumerate() {
            if r != c && row[c] != 0 {
                let f = row[c];
                for (v, &pv) in row.iter_mut().zip(pivot.iter()).take(k + 1) {
                    *v ^= gf::mul(f, pv);
                }
            }
        }
    }
    // Remaining 4-k equations must read 0 = 0.
    if m[k..].iter().any(|row| row[k] != 0) {
        return None;
    }
    let mut e = [0u8; 4];
    for (c, ec) in e.iter_mut().enumerate().take(k) {
        *ec = m[c][k];
    }
    Some(e)
}

use crate::encoding::{kdf as hkdf_sha256, random};
use crate::recovery_share::{RecoveryShare, V3Derivation};

/// Recovery code format version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeVersion {
    /// `2`: `(vdeviceId, vdeviceKey)` from the code alone.
    V2,
    /// `3`: `(vdeviceId, codeKey, fetchToken)` from the code; the bundle key
    /// also needs the erasable share.
    V3,
}

impl CodeVersion {
    /// The version character.
    pub fn char(self) -> u8 {
        match self {
            Self::V2 => VERSION,
            Self::V3 => VERSION_V3,
        }
    }

    fn from_symbol(sym: u8) -> Option<Self> {
        if Some(sym) == symbol_of(VERSION) {
            Some(Self::V2)
        } else if Some(sym) == symbol_of(VERSION_V3) {
            Some(Self::V3)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryCode
// ---------------------------------------------------------------------------

/// Map one input character to a symbol value, applying case folding and the
/// homoglyph rules `B→8`, `G→C`, `I→1`, `O→0`. `None` if it isn't in the
/// alphabet after mapping.
fn symbol_of(ch: u8) -> Option<u8> {
    let ch = match ch.to_ascii_uppercase() {
        b'B' => b'8',
        b'G' => b'C',
        b'I' => b'1',
        b'O' => b'0',
        other => other,
    };
    ALPHABET.iter().position(|&a| a == ch).map(|i| i as u8)
}

fn is_separator(ch: u8) -> bool {
    ch == b'-' || ch.is_ascii_whitespace()
}

/// A recovery code (SPEC §6.1). Secret: zeroized on drop, redacted in
/// `Debug`, compared in constant time.
///
/// `Display` prints the canonical 40 characters; the alternate form (`{:#}`)
/// prints ten space-separated groups of four for showing to a user.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    /// Canonical ASCII characters.
    chars: [u8; CODE_LEN],
}

impl RecoveryCode {
    /// Generate a fresh code: 34 uniform entropy symbols plus ECC.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; ENTROPY_LEN]);
        random(bytes.as_mut())?;
        // 256 is a multiple of 32, so masking is exactly uniform.
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        for (e, b) in entropy.iter_mut().zip(bytes.iter()) {
            *e = b & 0x1f;
        }
        Ok(Self::from_entropy_versioned(&entropy, CodeVersion::V2))
    }

    /// Build the code for given entropy symbols (each `< 32`). Deterministic;
    /// used by [`generate`](Self::generate) and for test vectors.
    ///
    /// # Panics
    /// If any symbol is `≥ 32`.
    pub fn from_entropy_symbols(entropy: &[u8; ENTROPY_LEN]) -> Self {
        Self::from_entropy_versioned(entropy, CodeVersion::V2)
    }

    /// The version-3 code for given entropy symbols (each `< 32`).
    /// Deterministic; used for test vectors.
    ///
    /// # Panics
    /// If any symbol is `≥ 32`.
    pub fn from_entropy_symbols_v3(entropy: &[u8; ENTROPY_LEN]) -> Self {
        Self::from_entropy_versioned(entropy, CodeVersion::V3)
    }

    fn from_entropy_versioned(entropy: &[u8; ENTROPY_LEN], version: CodeVersion) -> Self {
        assert!(entropy.iter().all(|&s| s < 32), "symbol out of range");
        let mut word = Zeroizing::new([0u8; WORD_LEN]);
        word[..ENTROPY_LEN].copy_from_slice(entropy);
        // G_ecc · ecc = G_ent · entropy (characteristic 2: minus is plus).
        let s = syndrome(&word);
        let ecc = solve(&[34, 35, 36, 37], s).expect("ECC columns are invertible");
        word[ENTROPY_LEN..].copy_from_slice(&ecc);
        debug_assert_eq!(syndrome(&word), [0; 4]);
        Self::from_word(&word, version)
    }

    fn from_word(word: &[u8; WORD_LEN], version: CodeVersion) -> Self {
        let mut chars = [0u8; CODE_LEN];
        chars[0] = version.char();
        chars[1] = IDENTIFIER;
        for (c, &w) in chars[2..].iter_mut().zip(word.iter()) {
            *c = ALPHABET[w as usize];
        }
        Self { chars }
    }

    /// Parse a code exactly (no error correction).
    ///
    /// Accepts upper or lower case, ignores spaces/whitespace and `-`, and
    /// applies the homoglyph mapping. Rejects anything that isn't 40 alphabet
    /// characters with identifier `0` and a valid ECC. A code that is
    /// otherwise well formed but carries a version other than `2` or `3`
    /// fails with [`Error::UnsupportedCodeVersion`]. To recover from typos,
    /// use [`candidates`](Self::candidates).
    pub fn parse(input: &str) -> Result<Self> {
        let raw = Raw::parse(input)?;
        if raw.erased != 0 {
            return Err(Error::BadRecoveryCode);
        }
        if syndrome(&raw.word) != [0; 4] {
            return Err(Error::BadRecoveryCode);
        }
        let version = raw.version()?;
        Ok(Self::from_word(&raw.word, version))
    }

    /// Every valid code within [`MAX_CORRECTIONS`] substitutions of `input`.
    ///
    /// The exact input comes first (if it is valid), then single, double and
    /// triple corrections. Corrections never touch the version or identifier.
    /// A character outside the alphabet (after homoglyph mapping) is treated
    /// as a known erasure and counts toward the three.
    ///
    /// Each yielded candidate is distinct. A typo'd code typically yields a
    /// few hundred triple-erasure candidates; the caller derives each one's
    /// `vdeviceId` ([`derive`](Self::derive)) and keeps the one the backend
    /// knows (paper p.31).
    ///
    /// Errors if the input isn't 40 characters (ignoring separators), or the
    /// identifier is wrong. An unknown version character fails with
    /// [`Error::UnsupportedCodeVersion`] when the rest of the code is a valid
    /// codeword, and with [`Error::BadRecoveryCode`] otherwise.
    pub fn candidates(input: &str) -> Result<Candidates> {
        let raw = Raw::parse(input)?;
        let version = raw.version()?;
        Self::candidates_from(raw, version)
    }

    /// Like [`candidates`](Self::candidates), but reads the code as `version`
    /// whatever its version character says, so a mistyped version character
    /// can still be matched against the backend.
    pub fn candidates_as(input: &str, version: CodeVersion) -> Result<Candidates> {
        Self::candidates_from(Raw::parse(input)?, version)
    }

    fn candidates_from(raw: Raw, version: CodeVersion) -> Result<Candidates> {
        if raw.erased.count_ones() as usize > MAX_CORRECTIONS {
            return Err(Error::BadRecoveryCode);
        }
        let forced: Vec<usize> = (0..WORD_LEN)
            .filter(|&i| raw.erased & (1u64 << i) != 0)
            .collect();
        let s = syndrome(&raw.word);
        Ok(Candidates {
            version,
            word: raw.word,
            syndrome: s,
            free: (0..WORD_LEN)
                .filter(|&i| raw.erased & (1u64 << i) == 0)
                .collect(),
            forced,
            extra: 0,
            combo: Vec::new(),
            started: false,
        })
    }

    /// The canonical 40-character string.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.chars).expect("ASCII")
    }

    /// Ten space-separated groups of four characters for user display.
    pub fn format_grouped(&self) -> String {
        format!("{self:#}")
    }

    /// The 34 entropy characters as ASCII (the KDF input).
    pub fn entropy_chars(&self) -> &[u8] {
        &self.chars[2..2 + ENTROPY_LEN]
    }

    /// This code's format version.
    pub fn version(&self) -> CodeVersion {
        CodeVersion::from_symbol(symbol_of(self.chars[0]).expect("canonical"))
            .expect("constructed with a supported version")
    }

    /// `(vdeviceId, key) = kdf(entropyChars, null,
    /// "BackupRecoveryCode_v<V>_0_" || did, 48)` split 16 + 32 (SPEC §6.1).
    ///
    /// For a version-2 code `key` is the bundle key. For a version-3 code it
    /// is `codeKey` (the first 48 bytes of the 80-byte derivation are the
    /// same), which opens nothing without the share: use
    /// [`bundle_key`](Self::bundle_key).
    pub fn derive(&self, did: &str) -> ([u8; 16], Zeroizing<[u8; 32]>) {
        let mut info = Vec::with_capacity(24 + did.len());
        info.extend_from_slice(b"BackupRecoveryCode_v");
        info.push(self.chars[0]);
        info.push(b'_');
        info.push(self.chars[1]);
        info.push(b'_');
        info.extend_from_slice(did.as_bytes());
        let mut okm = Zeroizing::new([0u8; 48]);
        hkdf_sha256(self.entropy_chars(), None, &info, okm.as_mut());
        let mut id = [0u8; 16];
        id.copy_from_slice(&okm[..16]);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&okm[16..]);
        (id, key)
    }

    /// The `vdeviceId` this code names.
    pub fn vdevice_id(&self, did: &str) -> [u8; 16] {
        self.derive(did).0
    }

    /// Version-3 derivation `(vdeviceId, codeKey, fetchToken) = kdf(
    /// entropyChars, null, "BackupRecoveryCode_v3_0_" || did, 80)` split
    /// 16 + 32 + 32. Fails for a version-2 code.
    pub fn derive_v3(&self, did: &str) -> Result<V3Derivation> {
        if self.version() != CodeVersion::V3 {
            return Err(Error::Malformed("not a version-3 recovery code"));
        }
        let mut info = Vec::with_capacity(24 + did.len());
        info.extend_from_slice(b"BackupRecoveryCode_v3_0_");
        info.extend_from_slice(did.as_bytes());
        let mut okm = Zeroizing::new([0u8; 80]);
        hkdf_sha256(self.entropy_chars(), None, &info, okm.as_mut());
        let mut vdevice_id = [0u8; 16];
        vdevice_id.copy_from_slice(&okm[..16]);
        let mut code_key = Zeroizing::new([0u8; 32]);
        code_key.copy_from_slice(&okm[16..48]);
        let mut fetch_token = Zeroizing::new([0u8; 32]);
        fetch_token.copy_from_slice(&okm[48..80]);
        Ok(V3Derivation {
            vdevice_id,
            code_key,
            fetch_token,
        })
    }

    /// `(vdeviceId, bundle key)` for this code. A version-2 code takes no
    /// share; a version-3 code requires one and fails with
    /// [`Error::RecoveryShareUnavailable`] without it.
    pub fn bundle_key(
        &self,
        did: &str,
        share: Option<&RecoveryShare>,
    ) -> Result<([u8; 16], Zeroizing<[u8; 32]>)> {
        match (self.version(), share) {
            (CodeVersion::V2, None) => Ok(self.derive(did)),
            (CodeVersion::V2, Some(_)) => {
                Err(Error::Malformed("version-2 recovery code takes no share"))
            }
            (CodeVersion::V3, Some(share)) => {
                let d = self.derive_v3(did)?;
                let key = d.vdevice_key(did, share);
                Ok((d.vdevice_id, key))
            }
            (CodeVersion::V3, None) => Err(Error::RecoveryShareUnavailable),
        }
    }
}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            for (i, chunk) in self.chars.chunks(4).enumerate() {
                if i > 0 {
                    f.write_str(" ")?;
                }
                f.write_str(core::str::from_utf8(chunk).expect("ASCII"))?;
            }
            Ok(())
        } else {
            f.write_str(self.as_str())
        }
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl PartialEq for RecoveryCode {
    fn eq(&self, other: &Self) -> bool {
        self.chars.ct_eq(&other.chars).into()
    }
}
impl Eq for RecoveryCode {}

impl core::str::FromStr for RecoveryCode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Input normalized to a 38-symbol word plus a bitmask of unreadable
/// positions (erased positions hold 0).
struct Raw {
    word: [u8; WORD_LEN],
    erased: u64,
    /// Symbol of the version character.
    version_sym: u8,
}

impl Raw {
    fn parse(input: &str) -> Result<Self> {
        let mut chars = Vec::with_capacity(CODE_LEN);
        for &b in input.as_bytes() {
            if !is_separator(b) {
                chars.push(b);
            }
        }
        if chars.len() != CODE_LEN {
            chars.zeroize();
            return Err(Error::BadRecoveryCode);
        }
        let version_sym = symbol_of(chars[0]);
        let header_ok = version_sym.is_some() && symbol_of(chars[1]) == symbol_of(IDENTIFIER);
        if !header_ok {
            chars.zeroize();
            return Err(Error::BadRecoveryCode);
        }
        let version_sym = version_sym.expect("checked");
        let mut word = [0u8; WORD_LEN];
        let mut erased = 0u64;
        for (i, &c) in chars[2..].iter().enumerate() {
            match symbol_of(c) {
                Some(v) => word[i] = v,
                None => erased |= 1 << i,
            }
        }
        chars.zeroize();
        Ok(Self {
            word,
            erased,
            version_sym,
        })
    }

    /// The supported version this input names. An unknown version on an
    /// otherwise valid codeword is [`Error::UnsupportedCodeVersion`].
    fn version(&self) -> Result<CodeVersion> {
        match CodeVersion::from_symbol(self.version_sym) {
            Some(v) => Ok(v),
            None if self.erased == 0 && syndrome(&self.word) == [0; 4] => {
                Err(Error::UnsupportedCodeVersion)
            }
            None => Err(Error::BadRecoveryCode),
        }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.word.zeroize();
    }
}

/// Iterator returned by [`RecoveryCode::candidates`].
///
/// For each erasure set `S` (all forced erasures plus 0..=3−|forced| free
/// positions, smallest sets first) it solves `G_S · e = syndrome` with all
/// four equations and yields `word + e` when consistent. With three erasures
/// that is three equations to solve and one to check. A solution with a zero
/// correction at a free position is skipped: the smaller set already
/// produced it.
pub struct Candidates {
    version: CodeVersion,
    word: [u8; WORD_LEN],
    syndrome: [u8; 4],
    forced: Vec<usize>,
    free: Vec<usize>,
    /// Number of free positions in the current combination size.
    extra: usize,
    /// Current combination over `free` (indices into `free`).
    combo: Vec<usize>,
    started: bool,
}

impl Candidates {
    /// Advance `combo` to the next combination of `extra` indices out of
    /// `free.len()`, moving to the next size when exhausted. Returns `false`
    /// when all sizes are done.
    fn advance(&mut self) -> bool {
        let n = self.free.len();
        let max_extra = MAX_CORRECTIONS - self.forced.len();
        if !self.started {
            self.started = true;
            self.extra = 0;
            self.combo.clear();
            return true;
        }
        // Next combination of the current size.
        let k = self.extra;
        let mut i = k;
        while i > 0 {
            i -= 1;
            if self.combo[i] < n - k + i {
                self.combo[i] += 1;
                for j in i + 1..k {
                    self.combo[j] = self.combo[j - 1] + 1;
                }
                return true;
            }
        }
        // Next size.
        if self.extra >= max_extra || self.extra + 1 > n {
            return false;
        }
        self.extra += 1;
        self.combo = (0..self.extra).collect();
        true
    }
}

impl Iterator for Candidates {
    type Item = RecoveryCode;

    fn next(&mut self) -> Option<RecoveryCode> {
        loop {
            if !self.advance() {
                return None;
            }
            let mut cols = [0usize; MAX_CORRECTIONS];
            let mut k = 0;
            for &p in &self.forced {
                cols[k] = p;
                k += 1;
            }
            for &ci in &self.combo {
                cols[k] = self.free[ci];
                k += 1;
            }
            let Some(e) = solve(&cols[..k], self.syndrome) else {
                continue;
            };
            let nf = self.forced.len();
            if e[nf..k].contains(&0) {
                continue;
            }
            let mut w = Zeroizing::new(self.word);
            for (&c, &ec) in cols[..k].iter().zip(e.iter()) {
                w[c] ^= ec;
            }
            debug_assert_eq!(syndrome(&w), [0; 4]);
            return Some(RecoveryCode::from_word(&w, self.version));
        }
    }
}

impl Drop for Candidates {
    fn drop(&mut self) {
        self.word.zeroize();
        self.syndrome.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(cols: &[[u8; 4]]) -> usize {
        let mut m: Vec<[u8; 4]> = cols.to_vec();
        let mut r = 0;
        for c in 0..4 {
            let Some(p) = (r..m.len()).find(|&i| m[i][c] != 0) else {
                continue;
            };
            m.swap(r, p);
            let iv = gf::inv(m[r][c]);
            for v in m[r].iter_mut() {
                *v = gf::mul(*v, iv);
            }
            let pivot = m[r];
            for (i, row) in m.iter_mut().enumerate() {
                if i != r && row[c] != 0 {
                    let f = row[c];
                    for (v, &pv) in row.iter_mut().zip(pivot.iter()) {
                        *v ^= gf::mul(f, pv);
                    }
                }
            }
            r += 1;
        }
        r
    }

    #[test]
    fn field_axioms() {
        for a in 1..32u8 {
            assert_eq!(gf::mul(a, gf::inv(a)), 1);
            assert_eq!(gf::mul(a, 1), a);
        }
        // x^5 = x^2 + 1
        assert_eq!(gf::mul(16, 2), 0b00101);
    }

    #[test]
    fn x2_x_c_irreducible_and_c_is_smallest() {
        let irreducible = |c: u8| (0..32u8).all(|x| gf::mul(x, x) ^ x ^ c != 0);
        assert!(!irreducible(0));
        assert!(irreducible(1));
    }

    /// Regenerate the matrix from the SPEC §6.1 rule.
    #[test]
    fn matrix_matches_rule() {
        const C: u8 = 1;
        // (a + bω)(d + eω), ω² = ω + c in characteristic 2.
        let m2 = |(a, b): (u8, u8), (d, e): (u8, u8)| {
            let be = gf::mul(b, e);
            (
                gf::mul(a, d) ^ gf::mul(C, be),
                gf::mul(a, e) ^ gf::mul(b, d) ^ be,
            )
        };
        // γ = 6 + ω is the primitive element t + ω with the smallest t.
        let order = |g: (u8, u8)| {
            let mut p = g;
            let mut k = 1u32;
            while p != (1, 0) {
                p = m2(p, g);
                k += 1;
            }
            k
        };
        let first_primitive = (0..32u8).find(|&t| order((t, 1)) == 1023).unwrap();
        assert_eq!(first_primitive, 6);
        let g = (6u8, 1u8);
        let mut z = (1u8, 0u8);
        for (k, col) in H.iter().enumerate() {
            let (a, b) = z;
            let n = gf::mul(a, a) ^ gf::mul(a, b) ^ gf::mul(C, gf::mul(b, b));
            assert_eq!(*col, [1, n, a, b], "column {k}");
            z = m2(z, g);
        }
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn all_column_triples_rank_three() {
        let mut count = 0;
        for i in 0..WORD_LEN {
            for j in i + 1..WORD_LEN {
                for k in j + 1..WORD_LEN {
                    assert_eq!(rank(&[H[i], H[j], H[k]]), 3, "({i},{j},{k})");
                    count += 1;
                }
            }
        }
        assert_eq!(count, 8436); // C(38,3)
    }

    #[test]
    fn ecc_columns_invertible() {
        assert_eq!(rank(&H[34..38]), 4);
    }

    #[test]
    fn generate_round_trip() {
        for _ in 0..200 {
            let c = RecoveryCode::generate().unwrap();
            let s = c.to_string();
            assert_eq!(s.len(), 40);
            assert!(s.starts_with("20"));
            assert_eq!(RecoveryCode::parse(&s).unwrap(), c);
            let grouped = format!("{c:#}");
            assert_eq!(grouped.len(), 49);
            assert_eq!(RecoveryCode::parse(&grouped).unwrap(), c);
            let dashed = grouped.replace(' ', "-").to_lowercase();
            assert_eq!(RecoveryCode::parse(&dashed).unwrap(), c);
            let mut it = RecoveryCode::candidates(&s).unwrap();
            assert_eq!(it.next().unwrap(), c);
            assert!(it.next().is_none(), "valid code has no other candidates");
        }
    }

    #[test]
    fn homoglyphs() {
        // Find a code containing 8, C, 1 and 0 in the protected part.
        let entropy: [u8; ENTROPY_LEN] = core::array::from_fn(|i| (i * 11 + 3) as u8 % 32);
        let c = RecoveryCode::from_entropy_symbols(&entropy);
        let s = c.to_string();
        let swapped: String = s
            .chars()
            .enumerate()
            .map(|(i, ch)| match (i, ch) {
                (i, '8') if i >= 2 => 'B',
                (i, 'C') if i >= 2 => 'g',
                (i, '1') if i >= 2 => 'i',
                (i, '0') if i >= 2 => 'O',
                (_, ch) => ch,
            })
            .collect();
        assert_ne!(swapped, s);
        assert_eq!(RecoveryCode::parse(&swapped).unwrap(), c);
        // The identifier '0' may be typed as 'O'.
        let mut o = s.clone();
        o.replace_range(1..2, "O");
        assert_eq!(RecoveryCode::parse(&o).unwrap(), c);
    }

    #[test]
    fn rejects_bad_input() {
        let c = RecoveryCode::generate().unwrap();
        let s = c.to_string();
        // Wrong identifier.
        let mut t = s.clone();
        t.replace_range(1..2, "1");
        assert_eq!(RecoveryCode::parse(&t), Err(Error::BadRecoveryCode));
        assert!(RecoveryCode::candidates(&t).is_err());
        // An unknown version on a valid codeword is a distinct error.
        for v in ["4", "Z", "A"] {
            let mut t = s.clone();
            t.replace_range(0..1, v);
            assert_eq!(RecoveryCode::parse(&t), Err(Error::UnsupportedCodeVersion));
            assert_eq!(
                RecoveryCode::candidates(&t).err(),
                Some(Error::UnsupportedCodeVersion)
            );
        }
        // Version '3' on the same word is a different, valid code.
        let mut t = s.clone();
        t.replace_range(0..1, "3");
        let v3 = RecoveryCode::parse(&t).unwrap();
        assert_eq!(v3.version(), CodeVersion::V3);
        assert_ne!(v3, c);
        // Length.
        assert!(RecoveryCode::parse(&s[..39]).is_err());
        assert!(RecoveryCode::parse(&format!("{s}A")).is_err());
        assert!(RecoveryCode::candidates(&s[..39]).is_err());
        // Alphabet ('U' is valid; '!' and '*' are not).
        let mut t = s.clone();
        t.replace_range(10..11, "!");
        assert!(RecoveryCode::parse(&t).is_err());
        // Bad ECC.
        let mut t = s.clone();
        let orig = t.as_bytes()[20];
        let new = if orig == b'A' { "C" } else { "A" };
        t.replace_range(20..21, new);
        assert!(RecoveryCode::parse(&t).is_err());
    }

    fn corrupt(s: &str, positions: &[usize], seed: &mut u32) -> String {
        let mut b = s.as_bytes().to_vec();
        for &p in positions {
            let orig = symbol_of(b[p]).unwrap();
            *seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let delta = 1 + (*seed >> 16) as u8 % 31;
            b[p] = ALPHABET[(orig ^ delta) as usize];
        }
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn single_and_double_errors_corrected() {
        let mut seed = 7u32;
        for _ in 0..20 {
            let c = RecoveryCode::generate().unwrap();
            let s = c.to_string();
            for p in 2..CODE_LEN {
                let t = corrupt(&s, &[p], &mut seed);
                assert!(RecoveryCode::parse(&t).is_err());
                assert!(RecoveryCode::candidates(&t).unwrap().any(|x| x == c));
            }
        }
        for _ in 0..3 {
            let c = RecoveryCode::generate().unwrap();
            let s = c.to_string();
            for p in 2..CODE_LEN {
                for q in p + 1..CODE_LEN {
                    let t = corrupt(&s, &[p, q], &mut seed);
                    let found = RecoveryCode::candidates(&t).unwrap().any(|x| x == c);
                    assert!(found, "positions {p},{q}");
                }
            }
        }
    }

    #[test]
    fn single_error_is_first_candidate() {
        // A single error is at distance 1; no other codeword is within 1
        // (minimum distance 4), so the first candidate is the original.
        let c = RecoveryCode::generate().unwrap();
        let mut seed = 99;
        let t = corrupt(&c.to_string(), &[17], &mut seed);
        assert_eq!(RecoveryCode::candidates(&t).unwrap().next().unwrap(), c);
    }

    #[test]
    fn triple_errors_corrected() {
        let mut seed = 42u32;
        for n in 0..60 {
            let c = RecoveryCode::generate().unwrap();
            let s = c.to_string();
            let p = 2 + (n * 7) % 38;
            let q = 2 + (n * 13 + 5) % 38;
            let r = 2 + (n * 29 + 11) % 38;
            if p == q || q == r || p == r {
                continue;
            }
            let t = corrupt(&s, &[p, q, r], &mut seed);
            let all: Vec<_> = RecoveryCode::candidates(&t).unwrap().collect();
            assert!(all.contains(&c), "positions {p},{q},{r}");
            // Distinct candidates.
            for (i, a) in all.iter().enumerate() {
                assert!(!all[i + 1..].contains(a));
            }
        }
    }

    #[test]
    fn unreadable_chars_are_erasures() {
        let c = RecoveryCode::generate().unwrap();
        let mut s = c.to_string();
        s.replace_range(5..6, "?");
        s.replace_range(30..31, "*");
        assert!(RecoveryCode::candidates(&s).unwrap().any(|x| x == c));
        // Plus one substitution.
        let mut seed = 3;
        let t = corrupt(&s, &[12], &mut seed);
        assert!(RecoveryCode::candidates(&t).unwrap().any(|x| x == c));
        // Four unreadable characters is too many.
        let mut u = s.clone();
        u.replace_range(7..8, "?");
        u.replace_range(8..9, "?");
        assert!(RecoveryCode::candidates(&u).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let c = RecoveryCode::generate().unwrap();
        assert!(!format!("{c:?}").contains(&c.to_string()[2..10]));
    }
}
