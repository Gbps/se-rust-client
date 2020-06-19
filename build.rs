extern crate protoc_rust;

fn main() {
    protoc_rust::Codegen::new()
        .out_dir("src/source/protos")
        .inputs(&["protos/netmessages.proto"])
        .include("protos")
        .run()
        .expect("protoc");
}