use rust_embed::Embed;

#[derive(Embed)]
#[folder = "resource/"]
struct Assets;

pub fn load_asset_text_file(name: String) -> String {
  let file = Assets::get(&name).unwrap();
  String::from_utf8(file.data.to_vec()).unwrap()
}
