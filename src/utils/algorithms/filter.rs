use pcap::{Packet};

pub fn is_eapol(packet: Packet<'_>) -> bool{
    let header_len: usize = u16::from_le_bytes([packet.data[2], packet.data[3]]) as usize;

    let radiotap_header: &[u8] = &packet.data[..header_len];
    let packet_data: &[u8] = &packet.data[header_len..];


    return false; 
}