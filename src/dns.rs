// Copy from https://github.com/EmilHernvall/dnsguide

#![allow(clippy::upper_case_acronyms)]

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

pub struct DnsBuf<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl<'a> DnsBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        DnsBuf { buf, pos: 0 }
    }

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

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DnsHeader {
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

impl DnsHeader {
    pub const fn new() -> DnsHeader {
        DnsHeader {
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

    pub fn read(&mut self, buf: &mut DnsBuf<'_>) -> io::Result<()> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
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

    pub fn write(&self, buf: &mut DnsBuf<'_>) -> io::Result<()> {
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn to_num(self) -> u16 {
        match self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub const fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    pub fn read(&mut self, buf: &mut DnsBuf) -> io::Result<()> {
        buf.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buf.read_u16()?); // qtype
        let _ = buf.read_u16()?; // class

        Ok(())
    }

    pub fn write(&self, buf: &mut DnsBuf) -> io::Result<()> {
        buf.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buf.write_u16(typenum)?;
        buf.write_u16(1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    pub fn ttl(&self) -> u32 {
        match *self {
            Self::UNKNOWN { ttl, .. } => ttl,
            Self::A { ttl, .. } => ttl,
            Self::NS { ttl, .. } => ttl,
            Self::CNAME { ttl, .. } => ttl,
            Self::MX { ttl, .. } => ttl,
            Self::AAAA { ttl, .. } => ttl,
        }
    }

    pub fn name(&self) -> &str {
        match *self {
            Self::UNKNOWN { ref domain, .. } => domain,
            Self::A { ref domain, .. } => domain,
            Self::NS { ref domain, .. } => domain,
            Self::CNAME { ref domain, .. } => domain,
            Self::MX { ref domain, .. } => domain,
            Self::AAAA { ref domain, .. } => domain,
        }
    }

    pub fn read(buf: &mut DnsBuf) -> io::Result<DnsRecord> {
        let mut domain = String::new();
        buf.read_qname(&mut domain)?;

        let qtype_num = buf.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let data_len = buf.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buf.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
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

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buf.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buf.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buf.read_u16()?;
                let mut mx = String::new();
                buf.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buf.step(data_len as usize);

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buf: &mut DnsBuf) -> io::Result<usize> {
        let start_pos = buf.pos;

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::A.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;
                buf.write_u16(4)?;

                let octets = addr.octets();
                buf.write_u8(octets[0])?;
                buf.write_u8(octets[1])?;
                buf.write_u8(octets[2])?;
                buf.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::NS.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos;
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos - (pos + 2);
                buf.set_u16(pos, size as u16);
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::CNAME.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos;
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos - (pos + 2);
                buf.set_u16(pos, size as u16);
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::MX.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos;
                buf.write_u16(0)?;

                buf.write_u16(priority)?;
                buf.write_qname(host)?;

                let size = buf.pos - (pos + 2);
                buf.set_u16(pos, size as u16);
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::AAAA.to_num())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;
                buf.write_u16(16)?;

                for octet in &addr.segments() {
                    buf.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                // logs::warn!("Skipping record: {:?}", self);
            }
        }

        Ok(buf.pos - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub const fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn read(&mut self, buf: &mut DnsBuf) -> io::Result<()> {
        self.header.read(buf)?;

        for _ in 0..self.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buf)?;
            self.questions.push(question);
        }

        for _ in 0..self.header.answers {
            let rec = DnsRecord::read(buf)?;
            self.answers.push(rec);
        }
        for _ in 0..self.header.authoritative_entries {
            let rec = DnsRecord::read(buf)?;
            self.authorities.push(rec);
        }
        for _ in 0..self.header.resource_entries {
            let rec = DnsRecord::read(buf)?;
            self.resources.push(rec);
        }

        Ok(())
    }

    pub fn write(&mut self, buf: &mut DnsBuf) -> io::Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buf)?;

        for question in &self.questions {
            question.write(buf)?;
        }
        for rec in &self.answers {
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
        "buffer overflow. DnsBuf is limited to 512 bytes",
    )
}
