use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// A TCP connection with a buffered reader, so bytes peeked during protocol
/// sniffing are not lost.
pub struct Conn {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Conn {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        // Match Go's default (TCP_NODELAY enabled on accepted sockets).
        let _ = stream.set_nodelay(true);
        let reader_stream = stream.try_clone()?;
        Ok(Conn {
            stream,
            reader: BufReader::new(reader_stream),
        })
    }

    /// Peek the first buffered byte without consuming it.
    pub fn peek_byte(&mut self) -> io::Result<u8> {
        let buf = self.reader.fill_buf()?;
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        Ok(buf[0])
    }

    /// Read one CRLF-terminated line, without the trailing CRLF.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut buf = Vec::new();
        let n = self.reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
            buf.pop();
        }
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn try_clone_stream(&self) -> io::Result<TcpStream> {
        self.stream.try_clone()
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(d)
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(d)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// TCP connect with a timeout, trying every resolved address (like Go's dialer).
pub fn dial_tcp(target: &str, timeout: Duration) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no addresses to dial",
        ));
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("dial failed")))
}

/// Bidirectional copy between a client `Conn` and an upstream stream.
/// Half-closes each direction so the peer sees EOF (like Go's CloseWrite).
pub fn tunnel(conn: &mut Conn, remote: TcpStream) {
    let client_w = match conn.try_clone_stream() {
        Ok(s) => s,
        Err(_) => return,
    };
    let remote_r = match remote.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let remote_w = match remote.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    let up = std::thread::spawn(move || {
        let mut rr = remote_r;
        let mut cw = client_w;
        let _ = io::copy(&mut rr, &mut cw);
        let _ = cw.shutdown(std::net::Shutdown::Write);
    });

    let mut rw = remote_w;
    let _ = io::copy(&mut *conn, &mut rw);
    let _ = rw.shutdown(std::net::Shutdown::Write);

    let _ = up.join();
}