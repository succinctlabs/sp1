use anyhow::Result;
use futures::{stream, Stream};
use itertools::Itertools;
use serde::Serialize;
use tonic::Streaming;

use crate::private::proto::Chunk;

const CHUNK_SIZE: usize = 3 * 1024 * 1024; // 3M

pub fn into_chunk_stream<T: Serialize>(
    message: &T,
) -> Result<impl Stream<Item = Chunk> + Send + Sync> {
    let message_encoded = bincode::serialize(&message)?;
    let chunks_iter = message_encoded.into_iter().chunks(CHUNK_SIZE);
    let mut chunks_iter = chunks_iter.into_iter().peekable();
    let mut chunks = vec![];

    while let Some(chunk) = chunks_iter.next() {
        chunks.push(Chunk {
            data: chunk.collect(),
            version: 1,
            is_last: chunks_iter.peek().is_none(),
        });
    }

    let stream = stream::iter(chunks);

    Ok(stream)
}

pub async fn consume_chunk_stream(mut stream: Streaming<Chunk>) -> Result<(Vec<u8>, u32)> {
    let mut encoded_message = vec![];
    let mut version = 0;
    let mut i = 0;

    while let Some(mut chunk) = stream.message().await? {
        tracing::debug!("CHUNK {i}");
        encoded_message.append(&mut chunk.data);
        if chunk.is_last {
            version = chunk.version;
            break;
        }
        i += 1;
    }

    Ok((encoded_message, version))
}
