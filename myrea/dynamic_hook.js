// Hook lower-level Windows API calls that catch everything
var hooked = [];

function hookNtDll(apiName, eventType) {
    var address = Module.findExportByName("ntdll.dll", apiName);
    if (address) {
        Interceptor.attach(address, {
            onEnter: function (args) {
                // Read the first argument as a wide string if it's a path
                try {
                    var path = args[0].readUtf16String();
                    if (path && path.length > 3) {
                        send(JSON.stringify({ type: eventType, target: path }));
                    }
                } catch (e) {}
            }
        });
        hooked.push(apiName);
    }
}

// Hook file creation at the NT level
hookNtDll("NtCreateFile", "FILE_CREATE");
hookNtDll("NtOpenFile", "FILE_OPEN");

// Hook registry at the NT level
hookNtDll("NtSetValueKey", "REGISTRY_WRITE");

// Hook process creation
var CreateProcessW = Module.findExportByName("kernelbase.dll", "CreateProcessW");
if (CreateProcessW) {
    Interceptor.attach(CreateProcessW, {
        onEnter: function (args) {
            try {
                var cmd = args[1].readUtf16String();
                if (cmd) send(JSON.stringify({ type: "PROCESS_CREATE", target: cmd }));
            } catch(e) {}
        }
    });
}

send(JSON.stringify({ type: "INFO", target: "Hooks loaded: " + hooked.join(", ") }));