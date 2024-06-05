#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn xdp_ebpf_tproxy(ctx: XdpContext) -> u32 {
    match try_xdp_ebpf_tproxy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_ebpf_tproxy(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    if (source_addr >> 24 == 192 && dst_addr >> 24 == 192) {
        return Ok(xdp_action::XDP_PASS);
    }
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let source_port = u16::from_be(unsafe { (*tcphdr).source });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

    let data = ctx.data();
    let data_end = ctx.data_end();
    let offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;

    if data + offset > data_end {
        info!(
            &ctx,
            "Data out of bounds ({:i}:{} => {:i}:{}", source_addr, source_port, dst_addr, dst_port,
        );

        return Ok(xdp_action::XDP_PASS);
    }
    let data_len = data_end - (data + offset);

    info!(
        &ctx,
        "Data is correct: ({:i}:{} => {:i}:{}, length: {}",
        source_addr,
        source_port,
        dst_addr,
        dst_port,
        data_len,
    );
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
