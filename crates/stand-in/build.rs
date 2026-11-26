fn main() {
   // GNU ld omits the note unless asked; Apple ld rejects --build-id.
   if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
      println!("cargo:rustc-cdylib-link-arg=-Wl,--build-id=sha1");
   }
}
