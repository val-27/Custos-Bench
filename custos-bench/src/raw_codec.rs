//! Passthrough gRPC codec.
//!
//! `tonic` prepends the 5-byte gRPC frame header itself. This codec copies
//! pre-loaded `.pb` bytes into the encode buffer and never parses them, so
//! malformed varints and nesting bombs leave the client intact.

use bytes::{Buf, BufMut, Bytes};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

/// Codec whose encode and decode items are raw protobuf message bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawCodec;

#[derive(Debug, Default, Clone, Copy)]
pub struct RawEncoder;

#[derive(Debug, Default, Clone, Copy)]
pub struct RawDecoder;

impl Codec for RawCodec {
    type Encode = Bytes;
    type Decode = Bytes;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        RawEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        RawDecoder
    }
}

impl Encoder for RawEncoder {
    type Item = Bytes;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        // Copy the pre-loaded .pb slice verbatim. No protobuf parse, no
        // length check, no 5-byte frame: tonic's EncodeBody writes the
        // compression flag and the big-endian length around this buffer.
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for RawDecoder {
    type Item = Bytes;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let len = src.remaining();
        let bytes = src.copy_to_bytes(len);
        Ok(Some(bytes))
    }
}

/// Encode `payload` the same way `RawEncoder` does, returning the unframed body.
///
/// The gRPC length prefix is intentionally absent: tonic adds it around this
/// buffer. Callers that need the on-wire frame should use [`frame_grpc`].
#[cfg(test)]
pub fn encode_raw(payload: &[u8]) -> Bytes {
    let mut dst = bytes::BytesMut::with_capacity(payload.len());
    dst.put_slice(payload);
    dst.freeze()
}

/// Build the 5-byte uncompressed gRPC frame tonic would prepend.
#[cfg(test)]
pub fn frame_grpc(payload: &[u8]) -> Bytes {
    let mut dst = bytes::BytesMut::with_capacity(5 + payload.len());
    dst.put_u8(0);
    dst.put_u32(payload.len() as u32);
    dst.put_slice(payload);
    dst.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::future::Future;
    use std::task::{Context, Poll};
    use tonic::codec::EncodeBody;
    use tokio_stream::iter;

    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = futures_task_noop();
        let mut cx = Context::from_waker(&waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => continue,
            }
        }
    }

    fn futures_task_noop() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        unsafe fn clone(ptr: *const ()) -> RawWaker {
            RawWaker::new(ptr, &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    /// Drive `RawEncoder::encode` through tonic's client body so the test
    /// observes both the untouched payload and the 5-byte frame tonic adds.
    fn encode_through_tonic(payload: &'static [u8]) -> Bytes {
        let body = EncodeBody::new_client(
            RawEncoder,
            iter(vec![Ok::<_, Status>(Bytes::from_static(payload))]),
            None,
            None,
        );
        let collected = block_on(async move { body.collect().await.unwrap().to_bytes() });
        collected
    }

    #[test]
    fn encoder_writes_malformed_bytes_and_tonic_frames_them() {
        let malformed: &'static [u8] = b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
        let wire = encode_through_tonic(malformed);
        assert_eq!(wire[0], 0x00, "uncompressed flag");
        let len = u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize;
        assert_eq!(len, malformed.len());
        assert_eq!(&wire[5..], malformed);
        assert_eq!(encode_raw(malformed).as_ref(), malformed);
    }

    #[test]
    fn frame_grpc_matches_the_spec_header() {
        let payload = b"abc";
        let framed = frame_grpc(payload);
        assert_eq!(&framed[..5], &[0x00, 0x00, 0x00, 0x00, 0x03]);
        assert_eq!(&framed[5..], payload);
    }

    #[test]
    fn encoder_preserves_empty_and_large_payloads() {
        assert!(encode_raw(b"").is_empty());
        let large = vec![0xA5u8; 64 * 1024];
        let encoded = encode_raw(&large);
        assert_eq!(encoded.len(), large.len());
        assert_eq!(encoded[0], 0xA5);
        assert_eq!(encoded[encoded.len() - 1], 0xA5);
    }

    #[test]
    fn codec_associated_types_are_raw_bytes() {
        fn assert_codec<C: Codec<Encode = Bytes, Decode = Bytes>>() {}
        assert_codec::<RawCodec>();
        let mut codec = RawCodec;
        let _encoder: RawEncoder = codec.encoder();
        let _decoder: RawDecoder = codec.decoder();
    }
}
