//! Method dispatch table entry classification.
//!
//! The VB6 method table contains entries that point to different kinds of
//! implementations depending on whether the binary is P-Code or native
//! compiled. [`MethodEntry`] classifies each slot.

use crate::{
    addressmap::AddressMap,
    error::Error,
    project::PCodeMethod,
    util::{read_u16_le, read_u32_le},
};

/// Classification of a single entry in the method dispatch table.
///
/// Not every slot in the method table contains P-Code. Entries can be null,
/// point to native compiled code within the PE, or reference default
/// implementations in the VB6 runtime DLL (MSVBVM60.DLL).
#[derive(Debug)]
pub enum MethodEntry<'a> {
    /// Slot is null (VA == 0). No method implementation at this index.
    Null,
    /// P-Code method with a `mov edx, <RTMI>; call ProcCallEngine` stub.
    PCode(PCodeMethod<'a>),
    /// Native-compiled method within the PE image.
    Native {
        /// Virtual address of the native method body.
        va: u32,
    },
    /// Runtime default method in MSVBVM60.DLL (VA outside the PE image).
    Runtime {
        /// Virtual address pointing into the VB6 runtime DLL.
        va: u32,
    },
}

impl<'a> MethodEntry<'a> {
    /// Reads and classifies a single method table entry.
    ///
    /// Used by [`MethodIterator`](super::MethodIterator) and
    /// [`PCodeMethodIterator`](super::PCodeMethodIterator) to determine
    /// whether a method table slot is null, P-Code, native, or a runtime default.
    ///
    /// # Arguments
    ///
    /// * `map` - Address map for VA-to-offset resolution.
    /// * `methods_va` - Base VA of the method dispatch table.
    /// * `index` - Zero-based slot within the table.
    ///
    /// # Returns
    ///
    /// A [`MethodEntry`] variant indicating the slot's type:
    /// - [`Null`](MethodEntry::Null) if the VA is zero.
    /// - [`Runtime`](MethodEntry::Runtime) if the VA falls outside the PE image.
    /// - [`PCode`](MethodEntry::PCode) if the target starts with `0xBA` (P-Code stub).
    /// - [`Native`](MethodEntry::Native) otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the method table entry or the stub bytes at the
    /// target VA cannot be read.
    pub(crate) fn classify(
        map: &AddressMap<'a>,
        methods_va: u32,
        index: u16,
    ) -> Result<MethodEntry<'a>, Error> {
        let entry_va = methods_va.wrapping_add(u32::from(index).wrapping_mul(4));
        let entry_data = map.slice_from_va(entry_va, 4)?;
        let method_va = read_u32_le(entry_data, 0)?;

        if method_va == 0 {
            return Ok(MethodEntry::Null);
        }

        if !map.is_va_in_image(method_va) {
            return Ok(MethodEntry::Runtime { va: method_va });
        }

        // Read enough bytes to detect P-Code stub patterns and direct ProcDscInfo:
        //   Pattern 1: BA xx xx xx xx          (mov edx, <RTMI>)
        //   Pattern 2: 33 C0 BA xx xx xx xx   (xor eax,eax; mov edx, <RTMI>)
        //   Pattern 3: Direct ProcDscInfo pointer (first dword is a valid in-PE VA
        //              pointing to ObjectInfo, and proc_size at +0x08 is non-zero)
        let stub_data = map.slice_from_va(method_va, 12)?;
        let stub_head = stub_data.first_chunk::<3>().ok_or(Error::Truncated {
            needed: 3,
            available: stub_data.len(),
        })?;
        let is_stub = stub_head[0] == 0xBA || (stub_head == &[0x33, 0xC0, 0xBA]);

        if is_stub {
            let pcode = PCodeMethod::parse(map, methods_va, index)?;
            return Ok(MethodEntry::PCode(pcode));
        }

        // Check for direct ProcDscInfo pointer: first dword is a valid proc_table VA,
        // and proc_size (u16 at +0x08) is non-zero.
        let maybe_proc_table = read_u32_le(stub_data, 0)?;
        let maybe_proc_size = read_u16_le(stub_data, 8)?;
        if map.is_va_in_image(maybe_proc_table) && maybe_proc_size > 0 && maybe_proc_size < 0x8000 {
            // Looks like a valid ProcDscInfo — try to parse as P-Code
            if let Ok(pcode) = PCodeMethod::parse(map, methods_va, index) {
                return Ok(MethodEntry::PCode(pcode));
            }
        }

        Ok(MethodEntry::Native { va: method_va })
    }
}
