//! Just enough AML to describe the board's devices: names, devices, scopes,
//! the resource descriptors a `_CRS` holds, device properties, a thermal zone,
//! and the methods that start a TPM command and read a temperature.

use alloc::vec::Vec;

pub type Bytes = Vec<u8>;

const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const NAME_OP: u8 = 0x08;
const BYTE_PREFIX: u8 = 0x0a;
const WORD_PREFIX: u8 = 0x0b;
const DWORD_PREFIX: u8 = 0x0c;
const STRING_PREFIX: u8 = 0x0d;
const QWORD_PREFIX: u8 = 0x0e;
const SCOPE_OP: u8 = 0x10;
const BUFFER_OP: u8 = 0x11;
const PACKAGE_OP: u8 = 0x12;
const METHOD_OP: u8 = 0x14;
const EXT_OP: u8 = 0x5b;
const OP_REGION: u8 = 0x80;
const FIELD_OP: u8 = 0x81;
const DEVICE_OP: u8 = 0x82;
const THERMAL_ZONE_OP: u8 = 0x85;
const STALL_OP: u8 = 0x21;
const STORE_OP: u8 = 0x70;
const ADD_OP: u8 = 0x72;
const SUBTRACT_OP: u8 = 0x74;
const INCREMENT_OP: u8 = 0x75;
const MULTIPLY_OP: u8 = 0x77;
const DIVIDE_OP: u8 = 0x78;
const AND_OP: u8 = 0x7b;
const LEQUAL_OP: u8 = 0x93;
const LGREATER_OP: u8 = 0x94;
const IF_OP: u8 = 0xa0;
const WHILE_OP: u8 = 0xa2;
const RETURN_OP: u8 = 0xa4;
const LOCAL0_OP: u8 = 0x60;
const LOCAL1_OP: u8 = 0x61;
const ARG0_OP: u8 = 0x68;
const ARG2_OP: u8 = 0x6a;

const SYSTEM_MEMORY: u8 = 0;
const DWORD_ACCESS: u8 = 3;

const MEMORY32_FIXED: u8 = 0x86;
const EXTENDED_INTERRUPT: u8 = 0x89;
const QWORD_ADDRESS_SPACE: u8 = 0x8a;
const END_TAG: u8 = 0x79;

pub fn integer(value: u64) -> Bytes {
    match value {
        0 => alloc::vec![ZERO_OP],
        1 => alloc::vec![ONE_OP],
        2..=0xff => alloc::vec![BYTE_PREFIX, value as u8],
        0x100..=0xffff => [&[WORD_PREFIX][..], &(value as u16).to_le_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[DWORD_PREFIX][..], &(value as u32).to_le_bytes()].concat(),
        _ => [&[QWORD_PREFIX][..], &value.to_le_bytes()].concat(),
    }
}

pub fn string(text: &str) -> Bytes {
    [&[STRING_PREFIX][..], text.as_bytes(), &[0]].concat()
}

fn name_seg(name: &str) -> [u8; 4] {
    let mut seg = [b'_'; 4];
    seg[..name.len()].copy_from_slice(name.as_bytes());
    seg
}

/// A length as AML codes it: one byte below 64, else the low four bits and
/// up to three more bytes.
fn length_bytes(value: usize) -> Bytes {
    match value {
        0..=0x3f => alloc::vec![value as u8],
        0x40..=0xfff => alloc::vec![0x40 | (value & 0xf) as u8, (value >> 4) as u8],
        0x1000..=0xf_ffff => alloc::vec![0x80 | (value & 0xf) as u8, (value >> 4) as u8, (value >> 12) as u8],
        _ => alloc::vec![0xc0 | (value & 0xf) as u8, (value >> 4) as u8, (value >> 12) as u8, (value >> 20) as u8],
    }
}

/// `body` after the length of the package it is in, which counts itself.
fn package_length(body: &[u8]) -> Bytes {
    let mut size = 1;
    while length_bytes(body.len() + size).len() != size {
        size += 1;
    }
    length_bytes(body.len() + size)
}

fn package(op: &[u8], head: &[u8], body: &[u8]) -> Bytes {
    let inner = [head, body].concat();
    [op, &package_length(&inner), &inner].concat()
}

pub fn name(name: &str, value: &[u8]) -> Bytes {
    [&[NAME_OP][..], &name_seg(name), value].concat()
}

pub fn device(name: &str, body: &[Bytes]) -> Bytes {
    package(&[EXT_OP, DEVICE_OP], &name_seg(name), &body.concat())
}

pub fn thermal_zone(name: &str, body: &[Bytes]) -> Bytes {
    package(&[EXT_OP, THERMAL_ZONE_OP], &name_seg(name), &body.concat())
}

/// `Scope (_SB)` and the like, in the root: one segment.
pub fn root_scope(segment: &str, body: &[Bytes]) -> Bytes {
    package(&[SCOPE_OP], &name_seg(segment), &body.concat())
}

pub fn buffer(data: &[u8]) -> Bytes {
    package(&[BUFFER_OP], &integer(data.len() as u64), data)
}

pub fn array(elements: &[Bytes]) -> Bytes {
    package(&[PACKAGE_OP], &[elements.len() as u8], &elements.concat())
}

pub fn method(name: &str, args: u8, serialized: bool, body: &[Bytes]) -> Bytes {
    package(&[METHOD_OP], &[&name_seg(name)[..], &[args | (serialized as u8) << 3]].concat(), &body.concat())
}

pub fn ret(value: &[u8]) -> Bytes {
    [&[RETURN_OP][..], value].concat()
}

/// `ToUUID`'s buffer: the first three fields little-endian.
pub fn uuid(text: &str) -> Bytes {
    let digits: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    let byte = |i: usize| u8::from_str_radix(core::str::from_utf8(&digits[2 * i..2 * i + 2]).unwrap(), 16).unwrap();
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    buffer(&order.map(byte))
}

pub fn operation_region(name: &str, base: u32, length: u32) -> Bytes {
    [&[EXT_OP, OP_REGION][..], &name_seg(name), &[SYSTEM_MEMORY], &integer(base as u64), &integer(length as u64)].concat()
}

/// A field of 32-bit registers: each name with its offset in bytes.
pub fn dword_fields(region: &str, registers: &[(&str, u32)]) -> Bytes {
    let mut list = Vec::new();
    let mut at = 0;
    for (register, offset) in registers {
        if *offset > at {
            list.push(0);
            list.extend(length_bytes(8 * (*offset - at) as usize));
        }
        list.extend(name_seg(register));
        list.extend(length_bytes(32));
        at = offset + 4;
    }
    package(&[EXT_OP, FIELD_OP], &[&name_seg(region)[..], &[DWORD_ACCESS]].concat(), &list)
}

pub fn arg0() -> Bytes {
    alloc::vec![ARG0_OP]
}

pub fn arg2() -> Bytes {
    alloc::vec![ARG2_OP]
}

pub fn local0() -> Bytes {
    alloc::vec![LOCAL0_OP]
}

pub fn local1() -> Bytes {
    alloc::vec![LOCAL1_OP]
}

pub fn named(register: &str) -> Bytes {
    name_seg(register).to_vec()
}

pub fn equal(left: &[u8], right: &[u8]) -> Bytes {
    [&[LEQUAL_OP][..], left, right].concat()
}

pub fn greater(left: &[u8], right: &[u8]) -> Bytes {
    [&[LGREATER_OP][..], left, right].concat()
}

pub fn increment(target: &[u8]) -> Bytes {
    [&[INCREMENT_OP][..], target].concat()
}

pub fn bit_and(left: &[u8], right: &[u8]) -> Bytes {
    bit_and_into(left, right, &[ZERO_OP])
}

pub fn bit_and_into(left: &[u8], right: &[u8], target: &[u8]) -> Bytes {
    [&[AND_OP][..], left, right, target].concat()
}

pub fn add(left: &[u8], right: &[u8]) -> Bytes {
    [&[ADD_OP][..], left, right, &[ZERO_OP]].concat()
}

pub fn subtract(left: &[u8], right: &[u8]) -> Bytes {
    [&[SUBTRACT_OP][..], left, right, &[ZERO_OP]].concat()
}

pub fn multiply(left: &[u8], right: &[u8]) -> Bytes {
    [&[MULTIPLY_OP][..], left, right, &[ZERO_OP]].concat()
}

/// The quotient, with the remainder left alone.
pub fn divide(left: &[u8], right: &[u8]) -> Bytes {
    [&[DIVIDE_OP][..], left, right, &[ZERO_OP, ZERO_OP]].concat()
}

pub fn store(value: &[u8], into: &[u8]) -> Bytes {
    [&[STORE_OP][..], value, into].concat()
}

pub fn stall(microseconds: u8) -> Bytes {
    [&[EXT_OP, STALL_OP][..], &integer(microseconds as u64)].concat()
}

pub fn when(predicate: &[u8], body: &[Bytes]) -> Bytes {
    package(&[IF_OP], predicate, &body.concat())
}

pub fn repeat_while(predicate: &[u8], body: &[Bytes]) -> Bytes {
    package(&[WHILE_OP], predicate, &body.concat())
}

/// A resource template: the descriptors, then the end tag.
pub fn resources(descriptors: &[Bytes]) -> Bytes {
    let mut list = descriptors.concat();
    list.extend([END_TAG, 0]);
    buffer(&list)
}

pub fn memory32(base: u32, length: u32) -> Bytes {
    let mut d = alloc::vec![MEMORY32_FIXED, 9, 0, 1];
    d.extend(base.to_le_bytes());
    d.extend(length.to_le_bytes());
    d
}

/// What a memory range in a resource template is for.
#[derive(Clone, Copy)]
pub enum Role {
    /// Registers the device uses.
    Consumed,
    /// What a container offers the devices in it: the memory they address,
    /// or the registers they sit at.
    Produced,
}

/// A range of memory with fixed ends, not cacheable, read-write and without
/// translation, in the 64-bit address space descriptor.
pub fn qword_memory(role: Role, base: u64, length: u64) -> Bytes {
    const BODY_LENGTH: u16 = 43;
    const MEMORY: u8 = 0;
    const MIN_FIXED: u8 = 1 << 2;
    const MAX_FIXED: u8 = 1 << 3;
    const CONSUMER: u8 = 1;
    const READ_WRITE: u8 = 1;
    let consumed = matches!(role, Role::Consumed) as u8 * CONSUMER;
    let mut d = alloc::vec![QWORD_ADDRESS_SPACE];
    d.extend(BODY_LENGTH.to_le_bytes());
    d.extend([MEMORY, MIN_FIXED | MAX_FIXED | consumed, READ_WRITE]);
    for field in [0, base, base + length - 1, 0, length] {
        d.extend(field.to_le_bytes());
    }
    d
}

/// Level-triggered, active-high interrupts the device consumes, as the
/// interrupt controller numbers them.
pub fn interrupts(gsivs: &[u32], shared: bool) -> Bytes {
    let flags = 1 | (shared as u8) << 3;
    let length = 2 + 4 * gsivs.len() as u16;
    let mut d = alloc::vec![EXTENDED_INTERRUPT];
    d.extend(length.to_le_bytes());
    d.extend([flags, gsivs.len() as u8]);
    for gsiv in gsivs {
        d.extend(gsiv.to_le_bytes());
    }
    d
}

const PROPERTIES_UUID: &str = "daffd814-6eba-4d8c-8a91-bc9bbf4aa301";

/// What a property can be: a device property is an integer, a string, or a
/// list of them (a buffer is not one, and a property that is not valid makes
/// the OS drop every property of the device).
pub enum Value {
    Integer(u64),
    Text(&'static str),
    Integers(Vec<u64>),
}

fn encode(value: &Value) -> Bytes {
    match value {
        Value::Integer(v) => integer(*v),
        Value::Text(t) => string(t),
        Value::Integers(list) => array(&list.iter().map(|v| integer(*v)).collect::<Vec<_>>()),
    }
}

/// `Name (_DSD, ...)`: device properties.
pub fn properties(list: &[(&str, Value)]) -> Bytes {
    let entries: Vec<Bytes> = list.iter().map(|(key, value)| array(&[string(key), encode(value)])).collect();
    name("_DSD", &array(&[uuid(PROPERTIES_UUID), array(&entries)]))
}
