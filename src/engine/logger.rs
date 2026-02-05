use pcap::{Capture};
use crate::utils::algorithms::filter::parse_packet;

pub fn start(dev_name: &str){
    let mut cap = Capture::from_device(dev_name).unwrap()
                        .immediate_mode(true)
                        .open()
                        .unwrap();
    println!("Monitoring on {:?}", dev_name);
    while let Ok(packet) = cap.next_packet(){
        //filter here

      parse_packet(packet);

    }

}
