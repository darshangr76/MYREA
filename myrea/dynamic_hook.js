var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
if (CreateFileW) {
    Interceptor.attach(CreateFileW, {
        onEnter: function (args) {
            var filename = args[0].readUtf16String();
            if (filename) send(JSON.stringify({ type: "FILE_OPEN", target: filename }));
        }
    });
}

var CreateProcessW = Module.findExportByName("kernel32.dll", "CreateProcessW");
if (CreateProcessW) {
    Interceptor.attach(CreateProcessW, {
        onEnter: function (args) {
            var cmdLine = args[1].readUtf16String();
            if (cmdLine) send(JSON.stringify({ type: "PROCESS_CREATE", target: cmdLine }));
        }
    });
}

var InternetOpenUrlW = Module.findExportByName("wininet.dll", "InternetOpenUrlW");
if (InternetOpenUrlW) {
    Interceptor.attach(InternetOpenUrlW, {
        onEnter: function (args) {
            var url = args[1].readUtf16String();
            if (url) send(JSON.stringify({ type: "NETWORK_URL", target: url }));
        }
    });
}

var RegSetValueExW = Module.findExportByName("advapi32.dll", "RegSetValueExW");
if (RegSetValueExW) {
    Interceptor.attach(RegSetValueExW, {
        onEnter: function (args) {
            var valueName = args[1].readUtf16String();
            if (valueName) send(JSON.stringify({ type: "REGISTRY_WRITE", target: valueName }));
        }
    });
}
