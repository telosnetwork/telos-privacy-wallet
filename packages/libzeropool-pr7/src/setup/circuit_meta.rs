use bincode;
use bit_vec::BitVec;
use core::fmt;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CircuitMeta {
    pub num_gates: u32,
    pub buf: Vec<u8>,
    pub constraints: Vec<u8>,
    pub constraints_bit_len: usize,
}

impl fmt::Display for CircuitMeta {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let buf_hex = hex::encode(&self.buf);
        let constraints_hex = hex::encode(&self.constraints);

        write!(
            f,
            "CircuitMeta {{\n\
            \tnum_gates: {},\n\
            \tbuf ({} bytes, hex): 0x{},\n\
            \tconstraints ({} bytes, hex): 0x{}\n\
            }}",
            self.num_gates,
            self.buf.len(),
            buf_hex,
            self.constraints.len(),
            constraints_hex
        )
    }
}

impl CircuitMeta {
    pub fn new(num_gates: u32, buf: Vec<u8>, constraints: BitVec) -> Self {
        CircuitMeta {
            num_gates,
            buf,
            constraints_bit_len: constraints.len(),
            constraints: constraints.to_bytes(),
        }
    }

    pub fn bitvec_constraints(&self) -> BitVec {
        let mut bv = BitVec::from_bytes(&self.constraints);
        bv.truncate(self.constraints_bit_len);
        bv
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let encoded: Vec<u8> = bincode::serialize(self).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Bincode serialization error: {}", e),
            )
        })?;

        writer.write_all(&encoded)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut encoded = Vec::new();
        reader.read_to_end(&mut encoded)?;

        let decoded: Self = bincode::deserialize(&encoded).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Bincode deserialization error: {}", e),
            )
        })?;

        Ok(decoded)
    }
}
