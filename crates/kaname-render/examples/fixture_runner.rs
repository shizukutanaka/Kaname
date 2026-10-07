fn main() {
    let path = std::env::args().nth(1).expect("usage: fixture_runner <eml>");
    let raw = std::fs::read(path).expect("read eml");
    let env = kaname_render::parse(&raw).expect("parse");
    println!("ms_ptt_bad={} ms_authas_bad={} ms_ct_oat_bad={} ms_prvs_bad={}", env.ms_ptt_bad, env.ms_authas_bad, env.ms_ct_oat_bad, env.ms_prvs_bad);
    println!("autocrypt_bad={} openpgp_bad={} content_return_bad={} list_followup_bad={}", env.autocrypt_bad, env.openpgp_bad, env.content_return_bad, env.list_followup_bad);
}
