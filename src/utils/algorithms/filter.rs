use std::{collections::HashMap, str::from_utf8};

use pcap::{Packet};

struct PPacket{
    is_eapol: bool,
    packet_type : String,
    packet_len: u32,
    signal_strenght: i16,
    p_type: String,
    ra: String,
    ta: String,
    da: String,
    bssid: String,
    ssid: String
}

fn string_addres(byte_slice: &[u8]) -> String{
    let to_return: String = byte_slice.iter()
    .map(|f: &u8|format!("{:02x}", f))
    .collect::<Vec<String>>()
    .join(":");
    return to_return;
}

pub fn parse_packet(packet: Packet<'_>) //-> PPacket
{
    let header_len: usize = u16::from_le_bytes([packet.data[2], packet.data[3]]) as usize;

    let radiotap_header: &[u8] = &packet.data[..header_len];
    let packet_data: &[u8] = &packet.data[header_len..];

    let p_type: String = packet_data[0].to_string();
    let addres1: String = string_addres(&packet_data.get(4..10).unwrap_or(&[0]));
    let addres2: String = string_addres(&packet_data.get(10..16).unwrap_or(&[0]));
    let addres3: String = string_addres(&packet_data.get(16..22).unwrap_or(&[0]));
    println!("{:?}", [addres1, addres2, addres3])


 
}