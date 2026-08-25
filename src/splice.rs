#![cfg(target_os = "linux")]

use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[cfg(test)]
use std::task::{ready, Context, Poll};

#[cfg(test)]
use tokio::io::Interest;

#[cfg(test)]
const PIPE_CAPACITY_HINT: libc::c_int = 64 * 1024;
#[cfg(test)]
const SPLICE_CHUNK: usize = 1024 * 1024;
// Most admitted connections are idle or short-lived. Start each direction at
// 4 KiB (8 KiB per connection) and only pay for the former 32 KiB fast-path
// buffer after that direction has delivered sustained traffic. At the 35k
// admission ceiling, idle relay storage is about 274 MiB instead of 2.14 GiB.
// A busy direction grows between writes, so resizing cannot invalidate bytes
// that are waiting to be delivered.
const BUFFERED_INITIAL_CHUNK: usize = 4 * 1024;
const BUFFERED_FAST_CHUNK: usize = 32 * 1024;
const BUFFERED_GROW_AFTER_BYTES: u64 = 256 * 1024;
const ACCOUNT_FLUSH_BYTES: u64 = 16 * 1024 * 1024;

struct ShutdownOnDrop {
    client_fd: RawFd,
    upstream_fd: RawFd,
    armed: bool,
}

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if self.armed {
            force_shutdown_fd(self.client_fd);
            force_shutdown_fd(self.upstream_fd);
        }
    }
}

#[cfg(test)]
async fn copy_bidirectional<F>(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    half_close_timeout: Duration,
    account: F,
) -> io::Result<()>
where
    F: FnMut(u64, u64),
{
    // `copy_bidirectional` borrows sockets owned by the connection task. If
    // that task is aborted (for example after the service drain deadline),
    // the future is dropped without reaching the terminal error path below.
    // Force both TCP legs closed during cancellation before their owners are
    // dropped so no half-closed kernel state survives unwinding.
    let account = std::sync::Mutex::new(account);
    let mut client_to_upstream = Direction::new()?;
    let mut upstream_to_client = Direction::new()?;
    let client_fd = client.as_raw_fd();
    let upstream_fd = upstream.as_raw_fd();
    let mut shutdown_guard = ShutdownOnDrop {
        client_fd,
        upstream_fd,
        armed: true,
    };
    let client_to_upstream_finished = copy_direction(
        &mut client_to_upstream,
        &*client,
        &*upstream,
        &account,
        DirectionSide::ClientToUpstream,
    );
    let upstream_to_client_finished = copy_direction(
        &mut upstream_to_client,
        &*upstream,
        &*client,
        &account,
        DirectionSide::UpstreamToClient,
    );
    tokio::pin!(client_to_upstream_finished);
    tokio::pin!(upstream_to_client_finished);

    let first = tokio::select! {
        result = &mut client_to_upstream_finished => (DirectionSide::ClientToUpstream, result),
        result = &mut upstream_to_client_finished => (DirectionSide::UpstreamToClient, result),
    };

    let result = match first {
        (_, Err(error)) => Err(error),
        (DirectionSide::ClientToUpstream, Ok(())) => {
            match tokio::time::timeout(half_close_timeout, &mut upstream_to_client_finished).await {
                Ok(result) => result,
                Err(_) => Err(half_close_timeout_error()),
            }
        }
        (DirectionSide::UpstreamToClient, Ok(())) => {
            match tokio::time::timeout(half_close_timeout, &mut client_to_upstream_finished).await {
                Ok(result) => result,
                Err(_) => Err(half_close_timeout_error()),
            }
        }
    };

    if result.is_err() {
        force_shutdown_fd(client_fd);
        force_shutdown_fd(upstream_fd);
    } else {
        shutdown_guard.armed = false;
    }
    result
}

pub async fn copy_bidirectional_buffered<ClientAccount, UpstreamAccount>(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    half_close_timeout: Duration,
    client_account: ClientAccount,
    upstream_account: UpstreamAccount,
) -> io::Result<()>
where
    ClientAccount: FnMut(u64),
    UpstreamAccount: FnMut(u64),
{
    let client_fd = client.as_raw_fd();
    let upstream_fd = upstream.as_raw_fd();
    let mut shutdown_guard = ShutdownOnDrop {
        client_fd,
        upstream_fd,
        armed: true,
    };
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let client_to_upstream = copy_direction_buffered(client_read, upstream_write, client_account);
    let upstream_to_client = copy_direction_buffered(upstream_read, client_write, upstream_account);
    tokio::pin!(client_to_upstream);
    tokio::pin!(upstream_to_client);

    let first = tokio::select! {
        result = &mut client_to_upstream => (DirectionSide::ClientToUpstream, result),
        result = &mut upstream_to_client => (DirectionSide::UpstreamToClient, result),
    };
    let result = match first {
        (_, Err(error)) => Err(error),
        (DirectionSide::ClientToUpstream, Ok(())) => {
            match tokio::time::timeout(half_close_timeout, &mut upstream_to_client).await {
                Ok(result) => result,
                Err(_) => Err(half_close_timeout_error()),
            }
        }
        (DirectionSide::UpstreamToClient, Ok(())) => {
            match tokio::time::timeout(half_close_timeout, &mut client_to_upstream).await {
                Ok(result) => result,
                Err(_) => Err(half_close_timeout_error()),
            }
        }
    };
    if result.is_err() {
        force_shutdown_fd(client_fd);
        force_shutdown_fd(upstream_fd);
    } else {
        shutdown_guard.armed = false;
    }
    result
}

async fn copy_direction_buffered<R, W, Account>(
    mut source: R,
    mut destination: W,
    account: Account,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    Account: FnMut(u64),
{
    let mut buffer = vec![0u8; BUFFERED_INITIAL_CHUNK];
    let mut accounting = BatchedAccount::new(account);
    let mut delivered = 0u64;
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            destination.shutdown().await?;
            return Ok(());
        }
        destination.write_all(&buffer[..read]).await?;
        accounting.add(read as u64);
        delivered = delivered.saturating_add(read as u64);
        maybe_grow_buffer(&mut buffer, delivered);
    }
}

fn maybe_grow_buffer(buffer: &mut Vec<u8>, delivered: u64) {
    if buffer.len() < BUFFERED_FAST_CHUNK && delivered >= BUFFERED_GROW_AFTER_BYTES {
        buffer.resize(BUFFERED_FAST_CHUNK, 0);
    }
}

struct BatchedAccount<Account>
where
    Account: FnMut(u64),
{
    account: Account,
    pending: u64,
}

impl<Account> BatchedAccount<Account>
where
    Account: FnMut(u64),
{
    fn new(account: Account) -> Self {
        Self {
            account,
            pending: 0,
        }
    }

    fn add(&mut self, bytes: u64) {
        self.pending = self.pending.saturating_add(bytes);
        if self.pending >= ACCOUNT_FLUSH_BYTES {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.pending != 0 {
            (self.account)(std::mem::take(&mut self.pending));
        }
    }
}

impl<Account> Drop for BatchedAccount<Account>
where
    Account: FnMut(u64),
{
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
async fn copy_direction<F>(
    direction: &mut Direction,
    source: &TcpStream,
    destination: &TcpStream,
    account: &std::sync::Mutex<F>,
    side: DirectionSide,
) -> io::Result<()>
where
    F: FnMut(u64, u64),
{
    std::future::poll_fn(|context| {
        let result = direction.poll_copy(context, source, destination);
        let bytes = direction.take_accounted();
        if bytes != 0 {
            match side {
                DirectionSide::ClientToUpstream => (account.lock().unwrap())(bytes, 0),
                DirectionSide::UpstreamToClient => (account.lock().unwrap())(0, bytes),
            }
        }
        result
    })
    .await
}

#[derive(Clone, Copy)]
enum DirectionSide {
    ClientToUpstream,
    UpstreamToClient,
}

fn half_close_timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "half-closed TCP connection did not finish before deadline",
    )
}

fn force_shutdown_fd(fd: RawFd) {
    // A write-half shutdown alone cannot release a socket whose peer already
    // sent FIN; force both halves closed on a terminal proxy error/deadline.
    let _ = unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
}

#[cfg(test)]
fn shutdown_write(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::shutdown(fd, libc::SHUT_WR) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
struct Direction {
    pipe: Pipe,
    in_pipe: usize,
    unaccounted: u64,
    source_eof: bool,
    destination_shutdown: bool,
    finished: bool,
}

#[cfg(test)]
impl Direction {
    fn new() -> io::Result<Self> {
        Ok(Self {
            pipe: Pipe::new()?,
            in_pipe: 0,
            unaccounted: 0,
            source_eof: false,
            destination_shutdown: false,
            finished: false,
        })
    }

    fn poll_copy(
        &mut self,
        context: &mut Context<'_>,
        source: &TcpStream,
        destination: &TcpStream,
    ) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.in_pipe > 0 {
                ready!(destination.poll_write_ready(context))?;
                match destination.try_io(Interest::WRITABLE, || {
                    splice(self.pipe.read, destination.as_raw_fd(), self.in_pipe)
                }) {
                    Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Ok(written) => {
                        self.in_pipe -= written;
                        self.unaccounted = self.unaccounted.saturating_add(written as u64);
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Poll::Pending
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }

            if self.source_eof {
                if self.destination_shutdown {
                    return Poll::Ready(Ok(()));
                }
                match shutdown_write(destination.as_raw_fd()) {
                    Ok(()) => {
                        self.destination_shutdown = true;
                        self.finished = true;
                        return Poll::Ready(Ok(()));
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }

            ready!(source.poll_read_ready(context))?;
            match source.try_io(Interest::READABLE, || {
                splice(source.as_raw_fd(), self.pipe.write, SPLICE_CHUNK)
            }) {
                Ok(0) => self.source_eof = true,
                Ok(read) => self.in_pipe = read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn take_accounted(&mut self) -> u64 {
        std::mem::take(&mut self.unaccounted)
    }
}

#[cfg(test)]
fn splice(source: RawFd, destination: RawFd, len: usize) -> io::Result<usize> {
    loop {
        let result = unsafe {
            libc::splice(
                source,
                std::ptr::null_mut(),
                destination,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
struct Pipe {
    read: RawFd,
    write: RawFd,
}

#[cfg(test)]
impl Pipe {
    fn new() -> io::Result<Self> {
        let mut descriptors = [0; 2];
        let result =
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            // This is only a hint. A smaller kernel-selected pipe remains correct.
            libc::fcntl(descriptors[0], libc::F_SETPIPE_SZ, PIPE_CAPACITY_HINT);
        }
        Ok(Self {
            read: descriptors[0],
            write: descriptors[1],
        })
    }
}

#[cfg(test)]
impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read);
            libc::close(self.write);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn reset_on_drop(stream: TcpStream) {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let result = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast(),
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(result, 0, "failed to configure test TCP reset");
        drop(stream);
    }

    async fn assert_peer_closed(stream: &mut TcpStream) {
        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_millis(250), stream.read(&mut byte))
            .await
            .expect("opposite peer remained open after TCP reset");
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "unexpected data after TCP reset: {result:?}"
        );
    }

    #[test]
    fn buffered_accounting_batches_and_flushes_tail_on_drop() {
        let flushed = std::cell::RefCell::new(Vec::new());
        {
            let mut accounting = BatchedAccount::new(|bytes| flushed.borrow_mut().push(bytes));
            accounting.add(ACCOUNT_FLUSH_BYTES - 1);
            assert!(flushed.borrow().is_empty());
            accounting.add(1);
            assert_eq!(*flushed.borrow(), [ACCOUNT_FLUSH_BYTES]);
            accounting.add(17);
        }
        assert_eq!(*flushed.borrow(), [ACCOUNT_FLUSH_BYTES, 17]);
    }

    #[test]
    fn buffered_storage_grows_only_after_sustained_delivery() {
        let mut buffer = vec![0; BUFFERED_INITIAL_CHUNK];
        maybe_grow_buffer(&mut buffer, BUFFERED_GROW_AFTER_BYTES - 1);
        assert_eq!(buffer.len(), BUFFERED_INITIAL_CHUNK);
        maybe_grow_buffer(&mut buffer, BUFFERED_GROW_AFTER_BYTES);
        assert_eq!(buffer.len(), BUFFERED_FAST_CHUNK);
        maybe_grow_buffer(&mut buffer, u64::MAX);
        assert_eq!(buffer.len(), BUFFERED_FAST_CHUNK);
    }

    #[tokio::test]
    async fn buffered_preserves_large_early_and_continuing_traffic() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional_buffered(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(1),
                |_| {},
                |_| {},
            )
            .await
        });
        let early: Vec<u8> = (0..(BUFFERED_FAST_CHUNK * 3 + 517))
            .map(|index| (index % 251) as u8)
            .collect();
        upstream_peer.write_all(&early).await.unwrap();
        let mut received = vec![0; early.len()];
        client_peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, early);

        let request = vec![0x51; BUFFERED_FAST_CHUNK * 2 + 31];
        client_peer.write_all(&request).await.unwrap();
        let mut upstream_received = vec![0; request.len()];
        upstream_peer
            .read_exact(&mut upstream_received)
            .await
            .unwrap();
        assert_eq!(upstream_received, request);
        client_peer.shutdown().await.unwrap();
        let mut eof = [0; 1];
        assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);
        upstream_peer.shutdown().await.unwrap();
        assert_eq!(client_peer.read(&mut eof).await.unwrap(), 0);
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn buffered_handles_backpressure_partial_writes_and_accounts_delivery() {
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        };

        timeout(Duration::from_secs(5), async {
            let (mut client_peer, mut router_client) = connected_pair().await;
            let (mut upstream_peer, mut router_upstream) = connected_pair().await;
            let send_buffer: libc::c_int = 4096;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        router_upstream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&send_buffer as *const libc::c_int).cast(),
                        std::mem::size_of_val(&send_buffer) as libc::socklen_t,
                    )
                },
                0
            );
            let accounted = Arc::new(AtomicU64::new(0));
            let proxy_accounted = Arc::clone(&accounted);
            let proxy = tokio::spawn(async move {
                copy_bidirectional_buffered(
                    &mut router_client,
                    &mut router_upstream,
                    Duration::from_secs(1),
                    move |bytes| {
                        proxy_accounted.fetch_add(bytes, Ordering::Relaxed);
                    },
                    |_| {},
                )
                .await
            });

            let payload: Vec<u8> = (0..(BUFFERED_FAST_CHUNK * 16 + 123))
                .map(|index| (index % 239) as u8)
                .collect();
            let sent = payload.clone();
            let writer = tokio::spawn(async move {
                client_peer.write_all(&sent).await.unwrap();
                client_peer.shutdown().await.unwrap();
                client_peer
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut received = vec![0; payload.len()];
            upstream_peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            let mut client_peer = writer.await.unwrap();
            let mut eof = [0; 1];
            assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);
            upstream_peer.shutdown().await.unwrap();
            assert_eq!(client_peer.read(&mut eof).await.unwrap(), 0);
            proxy.await.unwrap().unwrap();
            assert_eq!(accounted.load(Ordering::Relaxed), payload.len() as u64);
        })
        .await
        .expect("buffered relay stalled under destination backpressure");
    }

    #[tokio::test]
    async fn buffered_handles_simultaneous_full_duplex_backpressure() {
        timeout(Duration::from_secs(5), async {
            let (mut client_peer, mut router_client) = connected_pair().await;
            let (mut upstream_peer, mut router_upstream) = connected_pair().await;
            let send_buffer: libc::c_int = 4096;
            for stream in [&router_client, &router_upstream] {
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            stream.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUF,
                            (&send_buffer as *const libc::c_int).cast(),
                            std::mem::size_of_val(&send_buffer) as libc::socklen_t,
                        )
                    },
                    0
                );
            }
            let proxy = tokio::spawn(async move {
                copy_bidirectional_buffered(
                    &mut router_client,
                    &mut router_upstream,
                    Duration::from_secs(1),
                    |_| {},
                    |_| {},
                )
                .await
            });

            let client_payload: Vec<u8> = (0..(BUFFERED_FAST_CHUNK * 8 + 17))
                .map(|index| (index % 239) as u8)
                .collect();
            let upstream_payload: Vec<u8> = (0..(BUFFERED_FAST_CHUNK * 8 + 29))
                .map(|index| (index % 233) as u8)
                .collect();
            let client_sent = client_payload.clone();
            let upstream_sent = upstream_payload.clone();
            let client = tokio::spawn(async move {
                client_peer.write_all(&client_sent).await.unwrap();
                client_peer.shutdown().await.unwrap();
                let mut received = Vec::new();
                client_peer.read_to_end(&mut received).await.unwrap();
                received
            });
            let upstream = tokio::spawn(async move {
                upstream_peer.write_all(&upstream_sent).await.unwrap();
                upstream_peer.shutdown().await.unwrap();
                let mut received = Vec::new();
                upstream_peer.read_to_end(&mut received).await.unwrap();
                received
            });

            assert_eq!(client.await.unwrap(), upstream_payload);
            assert_eq!(upstream.await.unwrap(), client_payload);
            proxy.await.unwrap().unwrap();
        })
        .await
        .expect("buffered relay stalled under simultaneous full-duplex backpressure");
    }

    #[tokio::test]
    async fn buffered_healthy_session_outlives_half_close_timeout() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let deadline = Duration::from_millis(30);
        let proxy = tokio::spawn(async move {
            copy_bidirectional_buffered(
                &mut router_client,
                &mut router_upstream,
                deadline,
                |_| {},
                |_| {},
            )
            .await
        });
        client_peer.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        upstream_peer.read_exact(&mut request).await.unwrap();
        tokio::time::sleep(deadline * 3).await;
        assert!(!proxy.is_finished());
        upstream_peer.write_all(b"response").await.unwrap();
        let mut response = [0; 8];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        client_peer.shutdown().await.unwrap();
        let mut eof = [0; 1];
        assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);
        upstream_peer.shutdown().await.unwrap();
        assert_eq!(client_peer.read(&mut eof).await.unwrap(), 0);
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn buffered_bounds_half_closed_peer() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional_buffered(
                &mut router_client,
                &mut router_upstream,
                Duration::from_millis(40),
                |_| {},
                |_| {},
            )
            .await
        });
        client_peer.shutdown().await.unwrap();
        let mut eof = [0; 1];
        assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);
        let result = timeout(Duration::from_secs(1), proxy)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(result.kind(), io::ErrorKind::TimedOut);
        assert_peer_closed(&mut client_peer).await;
        assert_peer_closed(&mut upstream_peer).await;
    }

    #[tokio::test]
    async fn buffered_reset_and_cancel_force_close_other_legs() {
        let (client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional_buffered(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(10),
                |_| {},
                |_| {},
            )
            .await
        });
        reset_on_drop(client_peer);
        assert!(timeout(Duration::from_millis(250), proxy)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert_peer_closed(&mut upstream_peer).await;

        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional_buffered(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(10),
                |_| {},
                |_| {},
            )
            .await
        });
        proxy.abort();
        let _ = proxy.await;
        assert_peer_closed(&mut client_peer).await;
        assert_peer_closed(&mut upstream_peer).await;
    }

    #[tokio::test]
    async fn bounds_peer_that_stays_open_after_receiving_fin() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;

        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                Duration::from_millis(50),
                |_, _| {},
            )
            .await
        });

        client_peer.write_all(b"request").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut request = [0u8; 7];
        upstream_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        let mut eof = [0u8; 1];
        assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);

        // Reproduces the production pattern: the backend has observed the
        // client's FIN but never closes its own write side. The router must
        // bound this half-closed state instead of retaining both sockets and
        // pipe pairs indefinitely.
        let result = timeout(Duration::from_secs(1), proxy)
            .await
            .expect("proxy task leaked after half-close")
            .unwrap()
            .unwrap_err();
        assert_eq!(result.kind(), io::ErrorKind::TimedOut);

        let late_write = upstream_peer.write(b"late response").await;
        if let Ok(written) = late_write {
            // A successful write can race with the RST delivery. Reading must
            // still observe that the proxy socket has gone away promptly.
            assert!(written <= b"late response".len());
        }
        let _ = timeout(Duration::from_secs(1), upstream_peer.read(&mut eof))
            .await
            .expect("upstream socket remained established after proxy cleanup");
        assert_eq!(client_peer.read(&mut eof).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn preserves_response_during_normal_half_close() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;

        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(1),
                |_, _| {},
            )
            .await
        });
        let backend = tokio::spawn(async move {
            let mut request = Vec::new();
            upstream_peer.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            upstream_peer.write_all(b"response").await.unwrap();
            upstream_peer.shutdown().await.unwrap();
        });

        client_peer.write_all(b"request").await.unwrap();
        client_peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        backend.await.unwrap();
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn healthy_bidirectional_session_outlives_half_close_timeout() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let half_close_timeout = Duration::from_millis(30);

        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                half_close_timeout,
                |_, _| {},
            )
            .await
        });

        client_peer.write_all(b"first request").await.unwrap();
        let mut first = [0u8; 13];
        upstream_peer.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"first request");
        upstream_peer.write_all(b"first response").await.unwrap();
        let mut response = [0u8; 14];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"first response");

        tokio::time::sleep(half_close_timeout * 3).await;
        assert!(
            !proxy.is_finished(),
            "healthy full-duplex session hit a whole-session timeout"
        );

        client_peer.write_all(b"second").await.unwrap();
        let mut second = [0u8; 6];
        upstream_peer.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"second");
        upstream_peer.write_all(b"reply").await.unwrap();
        let mut reply = [0u8; 5];
        client_peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");

        client_peer.shutdown().await.unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);
        upstream_peer.shutdown().await.unwrap();
        assert_eq!(client_peer.read(&mut eof).await.unwrap(), 0);
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn upstream_reset_immediately_releases_client() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(10),
                |_, _| {},
            )
            .await
        });

        reset_on_drop(upstream_peer);
        let result = timeout(Duration::from_millis(250), proxy)
            .await
            .expect("upstream reset waited for half-close deadline")
            .unwrap();
        assert!(result.is_err());
        assert_peer_closed(&mut client_peer).await;
    }

    #[tokio::test]
    async fn client_reset_immediately_releases_upstream() {
        let (client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(10),
                |_, _| {},
            )
            .await
        });

        reset_on_drop(client_peer);
        let result = timeout(Duration::from_millis(250), proxy)
            .await
            .expect("client reset waited for half-close deadline")
            .unwrap();
        assert!(result.is_err());
        assert_peer_closed(&mut upstream_peer).await;
    }

    #[tokio::test]
    async fn completed_direction_stays_ready_on_repoll() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                Duration::from_millis(50),
                |_, _| {},
            )
            .await
        });

        client_peer.shutdown().await.unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(upstream_peer.read(&mut eof).await.unwrap(), 0);

        // Waking the opposite direction must not turn the already completed
        // direction back into Pending and lose the half-close deadline.
        upstream_peer.write_all(b"wake").await.unwrap();
        let mut response = [0u8; 4];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"wake");

        let result = timeout(Duration::from_secs(1), proxy)
            .await
            .expect("completed direction lost its half-close deadline")
            .unwrap()
            .unwrap_err();
        assert_eq!(result.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn cancelling_proxy_force_closes_both_socket_legs() {
        let (mut client_peer, mut router_client) = connected_pair().await;
        let (mut upstream_peer, mut router_upstream) = connected_pair().await;
        let proxy = tokio::spawn(async move {
            copy_bidirectional(
                &mut router_client,
                &mut router_upstream,
                Duration::from_secs(30),
                |_, _| {},
            )
            .await
        });

        client_peer.write_all(b"in flight").await.unwrap();
        let mut request = [0u8; 9];
        upstream_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"in flight");
        assert!(!proxy.is_finished());

        proxy.abort();
        assert!(proxy.await.unwrap_err().is_cancelled());

        assert_peer_closed(&mut client_peer).await;
        assert_peer_closed(&mut upstream_peer).await;
    }
}
