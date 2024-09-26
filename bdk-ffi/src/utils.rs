use std::sync::Arc;
use bitcoin_ffi::Script;


pub fn script_to_asm_string(script: Arc<Script>) -> String{
    script.0.to_asm_string()
}
