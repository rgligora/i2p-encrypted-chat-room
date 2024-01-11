use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_hello_world() -> String {
    "Hello World".to_string()
}
