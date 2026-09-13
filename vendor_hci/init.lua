-- Entry point for -X lua_script and package-aware plugin loaders.
-- Wireshark 4.4 also scans sibling files; matching samsung_* require names prevent
-- duplicate execution. Keep all modules beside this file for that loader.
return require("samsung_dissector")
