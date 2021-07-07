extern crate rucy_elfgen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args().nth(1).unwrap();
    println!("Generate elf file: {}", arg);
    rucy_elfgen::generate(arg)
}
