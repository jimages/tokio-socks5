use byteorder::{BigEndian, WriteBytesExt};
use std::{io, rc::Rc};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use tokio;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

/***
 * construct the tcplistener and transfer the connections to function.
 */
#[tokio::main]
pub async fn main() -> io::Result<()> {
    // 设置好日志的打印
    pretty_env_logger::init();

    // 设置一个TcpLintener用于接收来自客户端的连接，开启一个socks5代理。
    let listener = TcpListener::bind("0.0.0.0:8888").await?;

    // 一直循环，不断接收一个新收到的连接，因为可能在同一个时刻需要接收上百个sock5的代理连接。
    loop {
        let (socket, addr) = listener.accept().await.unwrap();
        // 当创建一个新的连接之后，就spawn一下，让对新连接的处理不影响原有的不断接收新请求的TcpListener
        // 通过这样的方式来实现高效的同时处理多个连接。
        tokio::spawn(async move {
            // 将新创建了连接交给process完成具体的逻辑处理。
            match process(socket, addr).await {
                Ok(()) => {}
                Err(ref e) => {
                    error!("get error from address {:?} {:?}", addr, e);
                }
            };
        });
    }
}

/***
 * 处理每个独立的连接
 */
async fn process(mut socket: TcpStream, address: SocketAddr) -> io::Result<()> {
    info!("get coonection from {}", address);

    // 我们先设置buffer大小为4k
    let mut buf = [0u8; 4096];

    // 进入协商机制，与客户进行协商鉴权
    negotiate(&mut socket, &address, &mut buf).await?;

    // 与客户端进行对于的连接，例如连接或者监听或者udp绑定
    request(socket, &mut buf).await?;

    Ok(())
}

/***
 * 与客户端进行协商鉴权
 */
async fn negotiate(socket: &mut TcpStream, addr: &SocketAddr, buf: &mut [u8]) -> io::Result<()> {
    // 读取前两个bytes，为ver和nmethods,如果没读取到，则返回错误。
    socket.read_exact(&mut buf[0..2]).await?;

    // 如果第一个字节不是0x05那么说明，该连接不是有效的sock5连接，断开连接
    if buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "only the sock5 protocol is supported",
        ));
    }

    // 获得nmethods
    let nmethods = buf[1] as usize;

    // 获得所有的methods
    socket.read_exact(&mut buf[0..nmethods]).await?;

    // 遍历所有的method
    let mut noauth_supported = false;
    for i in 0..nmethods {
        if buf[i] == 0x00 {
            noauth_supported = true;
        }
    }

    // 为了实现方便，这里我们只支持noauth协商模式
    if !noauth_supported {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "we only support noauthorization but client don't",
        ));
    }

    // 向客户端发送选择noauth鉴权。
    socket.write(&[0x05u8, 0x00_u8]).await?;
    socket.flush().await?;

    Ok(())
}
/**
 * 代理客户端进行连接的构建，包括连接或者监听或者udp绑定。
 */
async fn request(mut socket: TcpStream, buf: &mut [u8]) -> io::Result<()> {
    // 期望获得客户端发送的request数据，（这里我们只获取前6字节）
    socket.read_exact(&mut buf[0..6]).await?;

    if buf[0] == 0x05u8 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "only the sock5 protocol is supported",
        ));
    }
    let command = buf[1];
    let atype = buf[3];
    let mut tg_addr: Option<SocketAddr> = None;

    // 先根据atype获取目标地址
    match atype {
        0x01 => {
            // 如果是ipv4地址，则读取ipv4地址到tg_addr中，同时读取端口放入到addr中。
            socket.read_exact(&mut buf[0..6]).await?;
            let mut addrv4: [u8; 4] = std::default::Default::default();
            addrv4.clone_from_slice(&buf[0..4]);
            tg_addr = Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addrv4),
                buf[4..6].as_ref().read_u16().await?,
            )));
        }
        0x03 => {
            // 如果是域名则，则需要进行解析，然后填入地址中，并放入对于端口到addr中。
            socket.read_exact(&mut buf[0..1]).await?;
            let domainname_len = buf[6..7].as_ref().read_u8().await? as usize;
            info!("domainname len :{}", domainname_len);

            // 从tcp连接中读取域名和端口号
            socket.read_exact(&mut buf[0..domainname_len + 2]).await?;
            let port = buf[domainname_len..domainname_len + 2]
                .as_ref()
                .read_u16()
                .await?;

            // 调用tokio的lookup_host找到域名对于的dns地址
            if let Ok(domainname_str) = std::str::from_utf8(&buf[0..domainname_len]) {
                for addr in tokio::net::lookup_host((domainname_str, port)).await? {
                    tg_addr = Some(addr);
                }
            }
        }
        0x04 => {
            // 如果是ipv6,则填入地址中，并放入对于的端口，ipv6的地址是16个字节，端口2个字节
            socket.read_exact(&mut buf[0..16 + 2]).await?;
            let mut addrv6: [u8; 16] = std::default::Default::default();
            addrv6.clone_from_slice(&buf[0..16]);
            tg_addr = Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addrv6),
                buf[4..6].as_ref().read_u16().await?,
                0,
                0,
            )));
        }
        _ => {
            // 不支持其他的地址类型了，返回错误信息fail.
            error!("unsupported address type");
        }
    }

    // 没有获取到对于的ip地址，则说明是地址类型不支持，0x08错误码发送给客户端
    // 当解析失败的时候，给客户端发送错误码0x08
    if None == tg_addr {
        socket
            .write_all(&[0x05u8, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;
        return Err(io::Error::new(io::ErrorKind::Other, "unsupported address"));
    };
    let tg_addr = tg_addr.unwrap();

    /* 根据客户端command进行对于的操作 */
    match command {
        0x01 => {
            // 表示连接到对方服务器
            let mut target_stream = TcpStream::connect(&tg_addr).await?;
            let local_addr = target_stream.local_addr()?;
            buf[..3].clone_from_slice(&[0x05u8, 0x00, 0x00]);
            match local_addr {
                SocketAddr::V4(addr) => {
                    buf[3..3 + 4].clone_from_slice(&addr.ip().octets());
                    buf[7..9].as_mut().write_u16::<BigEndian>(addr.port())?;
                    socket.write_all(&buf[0..9]).await?;
                }
                SocketAddr::V6(addr) => {
                    buf[3..3 + 16].clone_from_slice(&addr.ip().octets());
                    buf[3 + 16..3 + 2 + 16]
                        .as_mut()
                        .write_u16::<BigEndian>(addr.port())?;
                    socket.write_all(&buf[0..9]).await?;
                }
            }
            let (mut remote_rx, mut remote_tx) = target_stream.split();
            let (mut local_rx, mut local_tx) = socket.split();
            let r2l = tokio::io::copy(&mut remote_rx, &mut local_tx);
            let l2r = tokio::io::copy(&mut local_rx, &mut remote_tx);
            let (r2l_result, l2r_result) = tokio::join!(r2l, l2r);
        }
        0x02 => {
            // 表示监听
        }
        0x03 => {
            // 表示upd绑定
        }
        _ => {
            // 不支持的command类型，返回错误码0x07
            socket
                .write_all(&[0x05u8, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not supported command.",
            ));
        }
    };
    Ok(())
}
