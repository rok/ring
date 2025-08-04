// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    aes::{self, Counter, OverlappingPartialBlock, BLOCK_LEN, ZERO_BLOCK},
    Overlapping,
    overlapping::IndexError,
    Nonce,
};
use crate::{
    cpu,
    error::{self, InputTooLongError},
    polyfill::sliceutil::overwrite_at_start,
};
use core::ops::RangeFrom;

#[cfg(target_arch = "x86_64")]
use aes::EncryptCtr32 as _;

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    all(target_arch = "arm", target_endian = "little"),
    target_arch = "x86",
    target_arch = "x86_64"
))]
use cpu::GetFeature as _;

#[derive(Clone)]
pub struct Key(DynKey);

impl Key {
    pub fn aes128(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        let cpu_features = cpu::features();
        let key = key_bytes.try_into().map_err(|_| error::Unspecified)?;
        let key = aes::KeyBytes::AES_128(key);
        Ok(Self(DynKey::new(key, cpu_features)?))
    }

    pub fn aes256(key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        let cpu_features = cpu::features();
        let key = key_bytes.try_into().map_err(|_| error::Unspecified)?;
        let key = aes::KeyBytes::AES_256(key);
        Ok(Self(DynKey::new(key, cpu_features)?))
    }

    #[inline]
    pub fn open_in_place<'in_out>(
        &mut self,
        nonce: Nonce,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], error::Unspecified> {
        self.open_within(nonce, in_out, 0..)
    }

    #[inline]
    pub fn open_within<'in_out>(
        &mut self,
        nonce: Nonce,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified> {
        let ciphertext_len = in_out
            .get(ciphertext_and_tag.clone())
            .ok_or(error::Unspecified)?
            .len();
        open(self, nonce, in_out, ciphertext_and_tag)?;
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub fn seal_in_place(&self, nonce: Nonce, in_out: &mut [u8]) -> Result<(), error::Unspecified> {
        seal(self, nonce, in_out)
    }
}

#[derive(Clone)]
enum DynKey {
    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86",
        target_arch = "x86_64"
    ))]
    AesHw(aes::hw::Key),

    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "arm", target_endian = "little"),
        target_arch = "x86",
        target_arch = "x86_64"
    ))]
    Simd(aes::vp::Key),

    Fallback(aes::fallback::Key),
}

impl DynKey {
    fn new(key: aes::KeyBytes, cpu_features: cpu::Features) -> Result<Self, error::Unspecified> {
        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        if let Some(aes) = cpu_features.get_feature() {
            let aes_key = aes::hw::Key::new(key, aes, cpu_features.get_feature());
            return Ok(Self::AesHw(aes_key));
        }

        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        if let Some(aes) = cpu_features.get_feature() {
            let aes_key = aes::vp::Key::new(key, aes);
            return Ok(Self::Simd(aes_key));
        }

        let _ = cpu_features;

        let aes_key = aes::fallback::Key::new(key);
        Ok(Self::Fallback(aes_key))
    }
}

const CHUNK_BLOCKS: usize = 3 * 1024 / 16;

#[inline(never)]
pub(super) fn seal(
    Key(key): &Key,
    nonce: Nonce,
    in_out: &mut [u8],
) -> Result<(), error::Unspecified> {
    let mut ctr = Counter::one(nonce);

    match key {
        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        DynKey::AesHw(aes_key) => {
            let (whole, remainder) = in_out.as_chunks_mut::<BLOCK_LEN>();
            aes_key.ctr32_encrypt_within(whole.as_flattened_mut().into(), &mut ctr);
            let remainder = OverlappingPartialBlock::new(remainder.into())
                .unwrap_or_else(|InputTooLongError { .. }| unreachable!());
            seal_finish(aes_key, remainder, ctr)
        }

        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        DynKey::Simd(c) => seal_strided(c, in_out, ctr),

        DynKey::Fallback(c) => seal_strided(c, in_out, ctr),
    }
}

#[cfg_attr(
    any(
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "arm", target_endian = "little"),
        target_arch = "x86",
        target_arch = "x86_64"
    ),
    inline(never)
)]
#[cfg_attr(
    any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86_64"
    ),
    cold
)]
fn seal_strided<A: aes::EncryptBlock + aes::EncryptCtr32>(
    aes_key: &A,
    in_out: &mut [u8],
    mut ctr: Counter,
) -> Result<(), error::Unspecified> {
    let (whole, remainder) = in_out.as_chunks_mut::<BLOCK_LEN>();

    for chunk in whole.chunks_mut(CHUNK_BLOCKS) {
        aes_key.ctr32_encrypt_within(chunk.as_flattened_mut().into(), &mut ctr);
    }

    let remainder = OverlappingPartialBlock::new(remainder.into())
        .unwrap_or_else(|InputTooLongError { .. }| unreachable!());
    seal_finish(aes_key, remainder, ctr)
}

fn seal_finish<A: aes::EncryptBlock>(
    aes_key: &A,
    remainder: OverlappingPartialBlock<'_>,
    ctr: Counter,
) -> Result<(), error::Unspecified> {
    let remainder_len = remainder.len();
    if remainder_len > 0 {
        let mut input = ZERO_BLOCK;
        overwrite_at_start(&mut input, remainder.input());
        let mut output = aes_key.encrypt_iv_xor_block(ctr.into(), input);
        output[remainder_len..].fill(0);
        remainder.overwrite_at_start(output);
    }

    Ok(())
}

#[inline(never)]
pub(super) fn open(
    Key(key): &Key,
    nonce: Nonce,
    in_out_slice: &mut [u8],
    src: RangeFrom<usize>,
) -> Result<(), error::Unspecified> {
    let mut ctr = Counter::one(nonce);

    match key {
        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        DynKey::AesHw(aes_key) => {
            let in_out =
                Overlapping::new(in_out_slice, src.clone()).map_err(error::erase::<IndexError>)?;
            let (whole, _) = in_out.input().as_chunks::<BLOCK_LEN>();
            let whole_len = whole.as_flattened().len();

            // Decrypt any remaining whole blocks.
            let whole = Overlapping::new(&mut in_out_slice[..(src.start + whole_len)], src.clone())
                .map_err(error::erase::<IndexError>)?;
            aes_key.ctr32_encrypt_within(whole, &mut ctr);

            let in_out_slice = match in_out_slice.get_mut(whole_len..) {
                Some(partial) => partial,
                None => unreachable!(),
            };
            let in_out = Overlapping::new(in_out_slice, src)
                .unwrap_or_else(|IndexError { .. }| unreachable!());
            let in_out = OverlappingPartialBlock::new(in_out)
                .unwrap_or_else(|InputTooLongError { .. }| unreachable!());
            open_finish(aes_key, in_out, ctr)
        }

        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        DynKey::Simd(k) => open_strided(k, in_out_slice, src, ctr),

        DynKey::Fallback(k) => open_strided(k, in_out_slice, src, ctr),
    }
}

#[cfg_attr(
    any(
        all(
            any(
                all(target_arch = "aarch64", target_endian = "little"),
                all(target_arch = "arm", target_endian = "little")
            ),
            target_feature = "neon"
        ),
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse"
        )
    ),
    inline(never)
)]
#[cfg_attr(
    any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86_64"
    ),
    cold
)]
fn open_strided<A: aes::EncryptBlock + aes::EncryptCtr32>(
    aes_key: &A,
    in_out_slice: &mut [u8],
    src: RangeFrom<usize>,
    mut ctr: Counter,
) -> Result<(), error::Unspecified> {
    let in_out = Overlapping::new(in_out_slice, src.clone()).map_err(error::erase::<IndexError>)?;
    let input = in_out.input();
    let input_len = input.len();

    let remainder_len = input_len % BLOCK_LEN;
    let whole_len = input_len - remainder_len;
    let in_prefix_len = src.start;

    {
        let mut chunk_len = CHUNK_BLOCKS * BLOCK_LEN;
        let mut output = 0;
        let mut input = in_prefix_len;
        loop {
            if whole_len - output < chunk_len {
                chunk_len = whole_len - output;
            }

            let ciphertext = &in_out_slice[input..][..chunk_len];
            let (ciphertext, leftover) = ciphertext.as_chunks::<BLOCK_LEN>();
            debug_assert_eq!(leftover.len(), 0);
            if ciphertext.is_empty() {
                break;
            }

            let chunk = Overlapping::new(
                &mut in_out_slice[output..][..(chunk_len + in_prefix_len)],
                in_prefix_len..,
            )
            .map_err(error::erase::<IndexError>)?;
            aes_key.ctr32_encrypt_within(chunk, &mut ctr);
            output += chunk_len;
            input += chunk_len;
        }
    }

    let in_out = Overlapping::new(&mut in_out_slice[whole_len..], src)
        .unwrap_or_else(|IndexError { .. }| unreachable!());
    let in_out = OverlappingPartialBlock::new(in_out)
        .unwrap_or_else(|InputTooLongError { .. }| unreachable!());

    open_finish(aes_key, in_out, ctr)
}

fn open_finish<A: aes::EncryptBlock>(
    aes_key: &A,
    remainder: OverlappingPartialBlock<'_>,
    ctr: Counter,
) -> Result<(), error::Unspecified> {
    if remainder.len() > 0 {
        let mut input = ZERO_BLOCK;
        overwrite_at_start(&mut input, remainder.input());
        remainder.overwrite_at_start(aes_key.encrypt_iv_xor_block(ctr.into(), input));
    }
    Ok(())
}
