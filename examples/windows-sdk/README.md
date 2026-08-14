# GlobalPlatform Windows SDK example

Configure this example against an extracted SDK archive:

```powershell
cmake -S . -B build -DCMAKE_PREFIX_PATH=C:\path\to\globalplatform-sdk-3.0.0-windows-x64
cmake --build build --config Release
$env:PATH = "C:\path\to\globalplatform-sdk-3.0.0-windows-x64\lib;$env:PATH"
.\build\Release\globalplatform_sdk_example.exe
```

The SDK exports `globalplatform::globalplatform` and
`gppcscconnectionplugin::gppcscconnectionplugin`. The PC/SC plugin is loaded by
the library at runtime; no smart-card reader is accessed by this smoke example.
