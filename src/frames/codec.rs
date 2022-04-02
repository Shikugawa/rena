// This trait defines encoding/decoding for frame objects.
pub trait Codec<T, U> {
    // It encodes internal objects into bytes.
    fn encode(from: T) -> U;

    // It decodes bytes into internal objects.
    fn decode(from: U) -> T;
}
