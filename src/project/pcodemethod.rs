//! P-Code method/procedure representation.
//!
//! A [`PCodeMethod`] provides access to a single P-Code procedure's metadata
//! (frame size, procedure size, flags) and a streaming iterator over its
//! decoded bytecode instructions.

use crate::{
    addressmap::AddressMap,
    error::Error,
    pcode::decoder::InstructionIterator,
    util::read_u32_le,
    vb::{
        constantpool::ConstantPool,
        controlprop::ControlPropertyIter,
        procedure::{self, ProcDscInfo},
    },
};

/// A single P-Code method/procedure within a VB6 object.
///
/// Provides access to the procedure's metadata (frame size, proc size)
/// and a streaming iterator over its decoded P-Code instructions.
#[derive(Debug)]
pub struct PCodeMethod<'a> {
    /// Procedure descriptor (RTMI) containing frame size, proc size, and flags.
    proc_dsc: ProcDscInfo<'a>,
    /// Raw P-Code byte stream (slice into the file buffer).
    pcode_bytes: &'a [u8],
    /// Base VA of the constant pool, used to resolve string/API references.
    data_const_va: u32,
    /// VA of the first P-Code byte (= proc_dsc_va - proc_size).
    pcode_va: u32,
    /// VA of the ProcDscInfo (RTMI) structure.
    proc_dsc_va: u32,
    /// VA of the call stub (`mov edx, <RTMI>`) or direct ProcDscInfo pointer.
    stub_va: u32,
}

impl<'a> PCodeMethod<'a> {
    /// Parses a P-Code method from a method table entry.
    ///
    /// The method table at `methods_va` contains 4-byte VA entries. For
    /// P-Code methods the VA points to a call stub
    /// (`mov edx, <rtmi_addr>; call ProcCallEngine`); this function
    /// detects the stub, extracts the RTMI address, parses the
    /// [`ProcDscInfo`], and locates the P-Code byte stream.
    ///
    /// # Arguments
    ///
    /// * `map` - Address map for VA-to-offset resolution.
    /// * `methods_va` - Base VA of the method dispatch table.
    /// * `index` - Zero-based slot within the table.
    ///
    /// # Returns
    ///
    /// A [`PCodeMethod`] with the parsed procedure descriptor, the raw
    /// P-Code bytes, and the constant pool base VA.
    ///
    /// # Errors
    ///
    /// Returns an error if any VA in the resolution chain (method table
    /// entry, stub, ProcDscInfo, ObjectInfo, or P-Code region) cannot be
    /// resolved to valid file offsets.
    pub fn parse(map: &AddressMap<'a>, methods_va: u32, index: u16) -> Result<Self, Error> {
        // Each method table entry is 4 bytes (a VA)
        let entry_va = methods_va.wrapping_add(u32::from(index).wrapping_mul(4));
        let entry_data = map.slice_from_va(entry_va, 4)?;
        let method_va = read_u32_le(entry_data, 0)?;

        // The method_va may point to a call stub or directly to ProcDscInfo.
        // Two known P-Code stub patterns:
        //   Pattern 1: BA xx xx xx xx (mov edx, <RTMI>; call ProcCallEngine)
        //   Pattern 2: 33 C0 BA xx xx xx xx 68 xx xx xx xx C3
        //              (xor eax,eax; mov edx, <RTMI>; push <ret>; ret)
        let stub_data = map.slice_from_va(method_va, 12)?;
        let stub_head = stub_data.first_chunk::<3>().ok_or(Error::Truncated {
            needed: 3,
            available: stub_data.len(),
        })?;

        let proc_dsc_va = if stub_head[0] == 0xBA {
            // Pattern 1: mov edx, imm32 at offset 0
            read_u32_le(stub_data, 1)?
        } else if stub_head == &[0x33, 0xC0, 0xBA] {
            // Pattern 2: xor eax,eax; mov edx, imm32 at offset 2
            read_u32_le(stub_data, 3)?
        } else {
            // Assume it's a direct pointer to ProcDscInfo
            method_va
        };

        // Parse ProcDscInfo — read MIN_SIZE first to get total_size, then re-read full
        let pdi_header = map.slice_from_va(proc_dsc_va, ProcDscInfo::MIN_SIZE)?;
        let pdi_tmp = ProcDscInfo::parse(pdi_header)?;
        let full_size = (pdi_tmp.total_size()? as usize).max(ProcDscInfo::MIN_SIZE);
        let pdi_data = map.slice_from_va(proc_dsc_va, full_size)?;
        let proc_dsc = ProcDscInfo::parse(pdi_data)?;

        // P-Code bytes are at [proc_dsc_va - proc_size .. proc_dsc_va]
        let proc_size = proc_dsc.proc_size()?;
        let pcode_va = proc_dsc_va.wrapping_sub(u32::from(proc_size));
        let pcode_data = map.slice_from_va(pcode_va, proc_size as usize)?;
        let pcode_bytes = pcode_data
            .get(..proc_size as usize)
            .ok_or(Error::Truncated {
                needed: proc_size as usize,
                available: pcode_data.len(),
            })?;

        // Get the constant pool base from ObjectInfo.lpConstants (+0x34)
        // ProcDscInfo+0x00 points to ObjectInfo (confirmed via ProcCallEngine_Body)
        let obj_info_va = proc_dsc.object_info_va()?;
        let oi_data = map.slice_from_va(obj_info_va, procedure::OBJECT_INFO_MIN_SIZE)?;
        let data_const_va = procedure::read_constants_va(oi_data)?;

        Ok(Self {
            proc_dsc,
            pcode_bytes,
            data_const_va,
            pcode_va,
            proc_dsc_va,
            stub_va: method_va,
        })
    }

    /// Returns the [`ProcDscInfo`] (RTMI) for this method.
    #[inline]
    pub fn proc_dsc(&self) -> &ProcDscInfo<'a> {
        &self.proc_dsc
    }

    /// Stack frame size for local variables.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ProcDscInfo field cannot be read.
    #[inline]
    pub fn frame_size(&self) -> Result<u16, Error> {
        self.proc_dsc.frame_size()
    }

    /// Size of the P-Code byte stream in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ProcDscInfo field cannot be read.
    #[inline]
    pub fn proc_size(&self) -> Result<u16, Error> {
        self.proc_dsc.proc_size()
    }

    /// Raw P-Code bytes for this method (slice into the file buffer).
    #[inline]
    pub fn pcode_bytes(&self) -> &'a [u8] {
        self.pcode_bytes
    }

    /// Constant pool base VA for resolving string/API references.
    #[inline]
    pub fn data_const_va(&self) -> u32 {
        self.data_const_va
    }

    /// VA of the first P-Code byte in the PE image.
    ///
    /// This is the address where the P-Code instruction stream begins,
    /// computed as `proc_dsc_va - proc_size`.
    #[inline]
    pub fn pcode_va(&self) -> u32 {
        self.pcode_va
    }

    /// VA of the ProcDscInfo (RTMI) structure in the PE image.
    ///
    /// The ProcDscInfo immediately follows the P-Code byte stream.
    #[inline]
    pub fn proc_dsc_va(&self) -> u32 {
        self.proc_dsc_va
    }

    /// VA of the call stub or direct ProcDscInfo pointer.
    ///
    /// This is the raw VA from the method dispatch table entry — the
    /// native stub code (`mov edx, <RTMI>; call ProcCallEngine`) that
    /// launches the P-Code interpreter for this method.
    #[inline]
    pub fn stub_va(&self) -> u32 {
        self.stub_va
    }

    /// Returns a streaming iterator over decoded P-Code instructions.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying procedure size cannot be read.
    pub fn instructions(&self) -> Result<InstructionIterator<'a>, Error> {
        Ok(InstructionIterator::new(
            self.pcode_bytes,
            self.proc_dsc.proc_size()?,
        ))
    }

    /// Iterates the procedure's local-variable cleanup table entries.
    ///
    /// The cleanup table describes resource-release thunks (BSTR free,
    /// VARIANT free, object Release) that the runtime invokes on procedure
    /// exit and on the error path. The table is **P-Code only** —
    /// native-compiled methods emit cleanup calls inline in their x86 code.
    ///
    /// This is a forwarder for [`ProcDscInfo::cleanup_entries`] kept on
    /// [`PCodeMethod`] for ergonomic consumer access; the underlying iterator
    /// is identical.
    #[inline]
    pub fn cleanup_entries(&self) -> ControlPropertyIter<'a> {
        self.proc_dsc.cleanup_entries()
    }

    /// Creates a [`ConstantPool`] reader for this method's constant pool.
    ///
    /// The constant pool is shared by all methods in the same object and
    /// is used to resolve `%s` operands (string literals, API stubs, etc.).
    pub fn constant_pool<'m>(&self, map: &'m AddressMap<'a>) -> ConstantPool<'m>
    where
        'a: 'm,
    {
        ConstantPool::new(map, self.data_const_va)
    }
}
