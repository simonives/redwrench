include!("src/cli.rs");

fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let cmd = <Cli as clap::CommandFactory>::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer).unwrap();
    std::fs::write(out_dir.join("redwrench.1"), buffer).unwrap();
    println!("cargo:rerun-if-changed=src/cli.rs");
}
