// Copy from https://github.com/EmilHernvall/dnsguide

#![allow(clippy::upper_case_acronyms)]

use core::{
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

use std::io;

use tracing::warn;

pub struct Buf<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl<'a> Buf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Buf { buf, pos: 0 }
    }

    #[cfg(any(feature = "https", feature = "tls"))]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read(&mut self) -> io::Result<u8> {
        if self.pos >= 512 {
            return Err(eof_err());
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> io::Result<u8> {
        if pos >= 512 {
            return Err(eof_err());
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> io::Result<&[u8]> {
        if start + len >= 512 {
            return Err(eof_err());
        }
        Ok(&self.buf[start..start + len])
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | self.read()? as u32;

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> io::Result<()> {
        let mut pos = self.pos;
        let mut jumped = false;

        let mut delim = "";
        loop {
            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) == 0xC0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2);
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> io::Result<()> {
        if self.pos >= 512 {
            return Err(eof_err());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        self.write(val)
    }

    fn write_u16(&mut self, val: u16) -> io::Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)
    }

    fn write_u32(&mut self, val: u32) -> io::Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)
    }

    fn write_qname(&mut self, qname: &str) -> io::Result<()> {
        for label in qname.split('.') {
            let len = label.len();

            label_len_check(len)?;

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)
    }

    fn set(&mut self, pos: usize, val: u8) {
        self.buf[pos] = val;
    }

    fn set_u16(&mut self, pos: usize, val: u16) {
        self.set(pos, (val >> 8) as u8);
        self.set(pos + 1, (val & 0xFF) as u8)
    }
}

#[cold]
#[inline(never)]
fn label_len_check(len: usize) -> io::Result<()> {
    if len > 0x34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Single label exceeds 63 characters of length",
        ));
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl From<u8> for ResultCode {
    fn from(num: u8) -> Self {
        match num {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => Self::NOERROR,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub id: u16,                    // 16 bits
    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit
    pub rescode: ResultCode,        // 4 bits
    pub checking_disabled: bool,    // 1 bit
    pub authed_data: bool,          // 1 bit
    pub z: bool,                    // 1 bit
    pub recursion_available: bool,  // 1 bit
    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl Header {
    pub const fn new() -> Header {
        Header {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buf: &mut Buf<'_>) -> io::Result<()> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buf.read_u16()?;
        self.answers = buf.read_u16()?;
        self.authoritative_entries = buf.read_u16()?;
        self.resource_entries = buf.read_u16()?;

        // Return the constant header size
        Ok(())
    }

    pub fn write(&self, buf: &mut Buf<'_>) -> io::Result<()> {
        buf.write_u16(self.id)?;

        (buf.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        ))?;

        (buf.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        ))?;

        buf.write_u16(self.questions)?;
        buf.write_u16(self.answers)?;
        buf.write_u16(self.authoritative_entries)?;
        buf.write_u16(self.resource_entries)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Query {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl From<Query> for u16 {
    fn from(val: Query) -> Self {
        match val {
            Query::UNKNOWN(x) => x,
            Query::A => 1,
            Query::NS => 2,
            Query::CNAME => 5,
            Query::MX => 15,
            Query::AAAA => 28,
        }
    }
}

impl From<u16> for Query {
    fn from(val: u16) -> Self {
        match val {
            1 => Query::A,
            2 => Query::NS,
            5 => Query::CNAME,
            15 => Query::MX,
            28 => Query::AAAA,
            v => Query::UNKNOWN(v),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    pub name: String,
    pub qtype: Query,
}

impl Question {
    const NEW: Self = Question::new(String::new(), Query::UNKNOWN(0));

    pub(super) const fn new(name: String, qtype: Query) -> Self {
        Self { name, qtype }
    }

    fn read(&mut self, buf: &mut Buf) -> io::Result<()> {
        buf.read_qname(&mut self.name)?;
        self.qtype = Query::from(buf.read_u16()?); // qtype
        let _ = buf.read_u16()?; // class

        Ok(())
    }

    fn write(&self, buf: &mut Buf) -> io::Result<()> {
        buf.write_qname(&self.name)?;
        buf.write_u16(self.qtype.into())?;
        buf.write_u16(1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Answer {
    domain: String,
    ttl: u32,
    record: Record,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Record {
    UNKNOWN { qtype: u16, data_len: u16 }, // 0
    A { addr: Ipv4Addr },                  // 1
    NS { host: String },                   // 2
    CNAME { host: String },                // 5
    MX { priority: u16, host: String },    // 15
    AAAA { addr: Ipv6Addr },               // 28
}

impl Answer {
    pub(super) const fn ttl(&self) -> u32 {
        self.ttl
    }

    #[allow(dead_code)]
    pub(super) const fn record(&self) -> &Record {
        &self.record
    }

    fn read(buf: &mut Buf) -> io::Result<Self> {
        let mut domain = String::new();
        buf.read_qname(&mut domain)?;

        let qtype_num = buf.read_u16()?;
        let qtype = Query::from(qtype_num);
        let _ = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let data_len = buf.read_u16()?;

        let record = match qtype {
            Query::A => {
                let raw_addr = buf.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );
                Record::A { addr }
            }
            Query::AAAA => {
                let raw_addr1 = buf.read_u32()?;
                let raw_addr2 = buf.read_u32()?;
                let raw_addr3 = buf.read_u32()?;
                let raw_addr4 = buf.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );
                Record::AAAA { addr }
            }
            Query::NS => {
                let mut host = String::new();
                buf.read_qname(&mut host)?;
                Record::NS { host }
            }
            Query::CNAME => {
                let mut host = String::new();
                buf.read_qname(&mut host)?;
                Record::CNAME { host }
            }
            Query::MX => {
                let priority = buf.read_u16()?;
                let mut host = String::new();
                buf.read_qname(&mut host)?;
                Record::MX { priority, host }
            }
            Query::UNKNOWN(_) => {
                buf.step(data_len as usize);
                Record::UNKNOWN {
                    qtype: qtype_num,
                    data_len,
                }
            }
        };

        Ok(Answer {
            domain,
            ttl,
            record,
        })
    }

    fn write(&self, buf: &mut Buf) -> io::Result<usize> {
        let start_pos = buf.pos;

        let domain = self.domain.as_str();
        let ttl = self.ttl;
        match self.record {
            Record::A { ref addr } => {
                buf.write_qname(domain)?;
                buf.write_u16(Query::A.into())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;
                buf.write_u16(4)?;

                let octets = addr.octets();
                buf.write_u8(octets[0])?;
                buf.write_u8(octets[1])?;
                buf.write_u8(octets[2])?;
                buf.write_u8(octets[3])?;
            }
            Record::NS { ref host } => {
                buf.write_qname(domain)?;
                buf.write_u16(Query::NS.into())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos;
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos - (pos + 2);
                buf.set_u16(pos, size as u16);
            }
            Record::CNAME { ref host } => {
                buf.write_qname(domain)?;
                buf.write_u16(Query::CNAME.into())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos;
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos - (pos + 2);
                buf.set_u16(pos, size as u16);
            }
            Record::MX { priority, ref host } => {
                buf.write_qname(domain)?;
                buf.write_u16(Query::MX.into())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos;
                buf.write_u16(0)?;

                buf.write_u16(priority)?;
                buf.write_qname(host)?;

                let size = buf.pos - (pos + 2);
                buf.set_u16(pos, size as u16);
            }
            Record::AAAA { ref addr } => {
                buf.write_qname(domain)?;
                buf.write_u16(Query::AAAA.into())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;
                buf.write_u16(16)?;

                for octet in &addr.segments() {
                    buf.write_u16(*octet)?;
                }
            }
            ref record => warn!("skipping record: {record:?}"),
        }

        Ok(buf.pos - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct Packet<A = Vec<Answer>> {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: A,
    pub authorities: Vec<Answer>,
    pub resources: Vec<Answer>,
}

impl Packet {
    pub const fn new() -> Packet {
        Packet {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub(super) fn read(&mut self, buf: &mut Buf) -> io::Result<()> {
        self.header.read(buf)?;

        for _ in 0..self.header.questions {
            let mut question = Question::NEW;
            question.read(buf)?;
            self.questions.push(question);
        }

        for _ in 0..self.header.answers {
            let rec = Answer::read(buf)?;
            self.answers.push(rec);
        }
        for _ in 0..self.header.authoritative_entries {
            let rec = Answer::read(buf)?;
            self.authorities.push(rec);
        }
        for _ in 0..self.header.resource_entries {
            let rec = Answer::read(buf)?;
            self.resources.push(rec);
        }

        Ok(())
    }
}

impl<'a> Packet<&'a [Answer]> {
    pub const fn new_ref() -> Self {
        Self {
            header: Header::new(),
            questions: Vec::new(),
            answers: &[],
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub(super) fn read(&mut self, buf: &mut Buf) -> io::Result<()> {
        self.header.read(buf)?;

        for _ in 0..self.header.questions {
            let mut question = Question::NEW;
            question.read(buf)?;
            self.questions.push(question);
        }

        for _ in 0..self.header.authoritative_entries {
            let rec = Answer::read(buf)?;
            self.authorities.push(rec);
        }
        for _ in 0..self.header.resource_entries {
            let rec = Answer::read(buf)?;
            self.resources.push(rec);
        }

        Ok(())
    }
}

impl<A> Packet<A>
where
    A: Deref<Target = [Answer]>,
{
    pub(super) fn write(&mut self, buf: &mut Buf) -> io::Result<()> {
        let answers = self.answers.deref();

        self.header.questions = self.questions.len() as u16;
        self.header.answers = answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buf)?;

        for question in &self.questions {
            question.write(buf)?;
        }
        for rec in answers {
            rec.write(buf)?;
        }
        for rec in &self.authorities {
            rec.write(buf)?;
        }
        for rec in &self.resources {
            rec.write(buf)?;
        }

        Ok(())
    }
}

#[cold]
#[inline(never)]
fn eof_err() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "buffer overflow. Buf is limited to 512 bytes",
    )
}
