#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod net;
mod providers;
mod selftest;
mod steam;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selftest") {
        let rest: Vec<String> = args
            .iter()
            .skip_while(|a| *a != "--selftest")
            .skip(1)
            .cloned()
            .collect();
        selftest::run(&rest);
        return;
    }

    tauri::Builder::default()
        .setup(|_app| {
            providers::load_custom_providers();

            std::thread::spawn(|| {
                net::ryuu_session();
                let _ = util::add_defender_exclusion();
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::steam_path,
            commands::steam_libraries,
            commands::game_install_info,
            commands::find_game_exe,
            commands::launch_game,
            commands::launch_exe,
            commands::ryuu_token,
            commands::add_defender_exclusion,
            commands::cache_dir_path,
            commands::pick_folder,
            commands::pick_exe,
            commands::steam_search,
            commands::library_games,
            commands::library_info,
            commands::delete_lua,
            commands::install_lua,
            commands::list_providers,
            commands::add_provider,
            commands::remove_provider,
            commands::download,
            commands::manifest_download,
            commands::get_json,
            commands::launch_steam,
            commands::reset_steam,
            commands::cloud_fix,
            commands::check_update,
            commands::open_url,
            commands::app_version,
            commands::load_theme,
            commands::save_theme
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
