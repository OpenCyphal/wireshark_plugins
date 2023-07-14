-- Common utility functions for Cyphal Wireshark plugins

--- Parses the CYPHAL_PATH environment variable to get an array of folders
--- @return table An array of folder paths from CYPHAL_PATH
local function parse_cyphal_path()
    local cyphal_path = os.getenv("CYPHAL_PATH")
    if not cyphal_path then
        return {}
    end

    local folders = {}
    local separator = package.config:sub(1,1) == '\\' and ';' or ':'  -- Windows uses ';', Unix uses ':'

    -- Split the path string by the separator
    for folder in string.gmatch(cyphal_path, "([^" .. separator .. "]+)") do
        table.insert(folders, folder)
    end

    return folders
end

--- Gets all first-level subfolders from an array of parent folders
--- @param parent_folders table An array of parent folder paths
--- @return table An array of all first-level subfolders
local function get_first_level_subfolders(parent_folders)
    local subfolders = {}

    for _, parent_folder in ipairs(parent_folders) do
        -- Use LuaFileSystem (lfs) if available, otherwise fall back to directory listing
        local lfs_available, lfs = pcall(require, "lfs")

        if lfs_available then
            -- Use LuaFileSystem
            for entry in lfs.dir(parent_folder) do
                if entry ~= "." and entry ~= ".." then
                    local full_path = parent_folder .. "/" .. entry
                    local attr = lfs.attributes(full_path)
                    if attr and attr.mode == "directory" then
                        table.insert(subfolders, full_path)
                    end
                end
            end
        else
            -- Fall back to using Dir.open() which is available in Wireshark's Lua environment
            local dir = Dir.open(parent_folder)
            if dir then
                local file = dir()
                while file do
                    if file ~= "." and file ~= ".." then
                        local full_path = parent_folder .. "/" .. file
                        -- Try to check if it's a directory by attempting to open it
                        local test_dir = Dir.open(full_path)
                        if test_dir then
                            table.insert(subfolders, full_path)
                            test_dir:close()
                        end
                    end
                    file = dir()
                end
                dir:close()
            end
        end
    end

    return subfolders
end

--- Gets all first-level subfolders from the CYPHAL_PATH environment variable
--- This is a convenience function that combines parse_cyphal_path and get_first_level_subfolders
--- @return table An array of all first-level subfolders from all paths in CYPHAL_PATH
local function get_cyphal_subfolders()
    local cyphal_paths = parse_cyphal_path()
    return get_first_level_subfolders(cyphal_paths)
end

--- Runs the nnvg command with the list of subfolders from CYPHAL_PATH
--- @param output_dir string Optional output directory (defaults to ~/.local/lib/wireshark/plugins/)
--- @return number, string Exit code and command output
local function run_nnvg_on_cyphal_subfolders(output_dir)
    local subfolders = get_cyphal_subfolders()

    if #subfolders == 0 then
        return -1, "No subfolders found in CYPHAL_PATH"
    end

    -- Build the command with all subfolders
    local output = output_dir or "~/.local/lib/wireshark/plugins/"
    local cmd = "nnvg --experimental-languages --target-language lua"

    for _, subfolder in ipairs(subfolders) do
        cmd = cmd .. " " .. subfolder
    end

    cmd = cmd .. " -O " .. output

    -- Execute the command
    local handle = io.popen(cmd .. " 2>&1")
    if not handle then
        return -1, "Failed to execute command: " .. cmd
    end

    local result = handle:read("*a")
    local success, exit_type, exit_code = handle:close()

    -- Return exit code and output
    if exit_type == "exit" then
        return exit_code, result
    else
        return -1, result
    end
end

-- Export the functions
return {
    parse_cyphal_path = parse_cyphal_path,
    get_first_level_subfolders = get_first_level_subfolders,
    get_cyphal_subfolders = get_cyphal_subfolders,
    run_nnvg_on_cyphal_subfolders = run_nnvg_on_cyphal_subfolders
}
