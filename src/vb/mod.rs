//! VB6 internal structure parsers.
//!
//! This module contains view types for every structure in the
//! VB6 executable format. Each type wraps a `&'a [u8]` slice that was
//! validated during construction and provides named accessor methods for
//! every field at its documented offset.
//!
//! # Structure Chain
//!
//! A VB6 PE follows a linked structure chain from the entry point:
//!
//! ```text
//! PE Entry Point
//!   └─ push <VA>  →  VbHeader (0x68 bytes)
//!                       ├─ lpProjectData  →  ProjectData (0x23C bytes)
//!                       │                      ├─ lpObjectTable  →  ObjectTable (0x54 bytes)
//!                       │                      │                      └─ lpObjectArray  →  PublicObjectDescriptor[] (0x30 each)
//!                       │                      │                           ├─ lpObjectInfo  →  ObjectInfo (0x38 bytes)
//!                       │                      │                           │                     ├─ lpMethods  →  Method dispatch table (4 bytes per slot)
//!                       │                      │                           │                     ├─ lpConstants  →  Constant pool
//!                       │                      │                           │                     └─ lpPrivateObject  →  PrivateObjectDescriptor (0x40 bytes)
//!                       │                      │                           │                           ├─ lpFuncTypDescs  →  FuncTypDesc pointer array
//!                       │                      │                           │                           └─ lpParamNames  →  Parameter name strings
//!                       │                      │                           └─ [if flag 0x01]  →  OptionalObjectInfo (0x40 bytes)
//!                       │                      │                                 ├─ lpControls  →  ControlInfo[] (0x28 each)
//!                       │                      │                                 └─ wPCodeCount, event offsets
//!                       │                      └─ lpExternalTable  →  ExternalTableEntry[] (8 bytes each)
//!                       ├─ lpGuiTable  →  GUITableEntry[] (variable-length, wFormCount entries)
//!                       └─ lpComRegisterData  →  ComRegData + ComRegObject linked list
//!
//! Method dispatch table entries:
//!   ├─ VA == 0                         →  Null slot
//!   ├─ VA outside PE (MSVBVM60.DLL)    →  Runtime default handler
//!   ├─ VA inside PE, byte[0] == 0xBA   →  P-Code stub (mov edx, <RTMI>; call ProcCallEngine)
//!   │    └─ RTMI  →  ProcDscInfo (variable-length, trails P-Code stream)
//!   │                  └─ lpObjectInfo  →  ObjectInfo (same struct as above)
//!   │                                      └─ lpConstants (offset 0x34)  →  Constant pool base
//!   └─ VA inside PE, byte[0] != 0xBA   →  Native compiled method
//! ```
//!
//! # Notes for Researchers
//!
//! - Microsoft never published the VB6 file format. All field names and
//!   layouts are from community reverse engineering (WKTVBDE, Semi-VBDecompiler,
//!   VBDec, Gen Digital research) or LLM hallucinated.
//! - The [`PrivateObjectDescriptor`](privateobj::PrivateObjectDescriptor) layout was reverse-engineered
//!   specifically for this crate by examining real binaries via BinaryNinja.
//! - Some structures (COM\_RegData, GUITable) remain completely undocumented.
//! - Field offsets and sizes are verified against MSVBVM60.DLL version 6.00.9848.

pub mod bstr;
pub mod comreg;
pub mod constantpool;
pub mod constants;
pub mod control;
pub mod controlprop;
pub mod eventname;
pub mod events;
pub mod exports;
pub mod external;
pub mod flags;
pub mod formdata;
pub mod functype;
pub mod guitable;
pub mod header;
pub mod object;
pub mod objecttable;
pub mod privateobj;
pub mod procedure;
pub mod projectdata;
pub mod projectinfo2;
pub mod property;
pub mod publicbytes;
pub mod varstub;
