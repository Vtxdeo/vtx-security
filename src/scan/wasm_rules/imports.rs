use std::collections::BTreeMap;

pub(super) fn classify_import(
    module: &str,
    name: &str,
    fs: &mut BTreeMap<String, Vec<String>>,
    net: &mut BTreeMap<String, Vec<String>>,
    process: &mut BTreeMap<String, Vec<String>>,
    env: &mut BTreeMap<String, Vec<String>>,
    time: &mut BTreeMap<String, Vec<String>>,
    random: &mut BTreeMap<String, Vec<String>>,
) {
    let module_lower = module.to_ascii_lowercase();
    let name_lower = name.to_ascii_lowercase();

    if module_lower.starts_with("wasi:filesystem")
        || module_lower.starts_with("wasi_snapshot_preview1")
            && matches!(
                name_lower.as_str(),
                "path_open"
                    | "path_create_directory"
                    | "path_unlink_file"
                    | "path_remove_directory"
                    | "path_rename"
                    | "path_link"
                    | "path_symlink"
                    | "fd_read"
                    | "fd_pread"
                    | "fd_write"
                    | "fd_pwrite"
                    | "fd_seek"
                    | "fd_readdir"
                    | "fd_filestat_get"
                    | "fd_filestat_set_times"
                    | "fd_fdstat_get"
                    | "fd_fdstat_set_flags"
                    | "fd_fdstat_set_rights"
                    | "fd_prestat_get"
                    | "fd_prestat_dir_name"
            )
    {
        push_import(fs, module, name);
        return;
    }

    if module_lower.starts_with("wasi:sockets")
        || module_lower.starts_with("wasi:network")
        || module_lower.starts_with("wasi_snapshot_preview1")
            && matches!(
                name_lower.as_str(),
                "sock_open"
                    | "sock_accept"
                    | "sock_bind"
                    | "sock_listen"
                    | "sock_connect"
                    | "sock_recv"
                    | "sock_send"
                    | "sock_shutdown"
                    | "sock_getpeeraddr"
                    | "sock_getlocaladdr"
            )
    {
        push_import(net, module, name);
        return;
    }

    if module_lower.starts_with("wasi_snapshot_preview1")
        && matches!(name_lower.as_str(), "proc_exit" | "proc_raise" | "thread_spawn")
    {
        push_import(process, module, name);
        return;
    }

    if module_lower.starts_with("wasi_snapshot_preview1")
        && matches!(
            name_lower.as_str(),
            "environ_get" | "environ_sizes_get" | "args_get" | "args_sizes_get"
        )
    {
        push_import(env, module, name);
        return;
    }

    if module_lower.starts_with("wasi_snapshot_preview1")
        && matches!(name_lower.as_str(), "clock_time_get" | "clock_res_get")
    {
        push_import(time, module, name);
        return;
    }

    if module_lower.starts_with("wasi_snapshot_preview1")
        && matches!(name_lower.as_str(), "random_get")
    {
        push_import(random, module, name);
    }
}

fn push_import(map: &mut BTreeMap<String, Vec<String>>, module: &str, name: &str) {
    map.entry(module.to_string())
        .or_default()
        .push(name.to_string());
}
