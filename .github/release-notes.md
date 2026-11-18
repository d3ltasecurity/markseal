**Public preview. Windows 11 only. The installer is not code-signed yet.**

Windows will show "Windows protected your PC" on first run: click **More info → Run anyway**.
Before you do, check the download against `SHA256SUMS`:

```powershell
Get-FileHash .\Markseal_*_x64-setup.exe -Algorithm SHA256
```

You can also verify that this installer was built by GitHub Actions from this repository:

```bash
gh attestation verify Markseal_*_x64-setup.exe --repo d3ltasecurity/markseal
```

What is tested and what is not: see [CHANGELOG.md](https://github.com/d3ltasecurity/markseal/blob/main/CHANGELOG.md) and the
"Known limitations" section of [SECURITY.md](https://github.com/d3ltasecurity/markseal/blob/main/SECURITY.md). In short:

- Tested on Windows 11 (25H2), by one person. Not tested on Windows 10 or macOS.
- The Microsoft WebView2 runtime that draws the window can still open a connection to
  Microsoft at start-up. Markseal itself sends nothing.
- No automatic updates. Watch this repository for new releases.

Found a security problem? Please report it privately, as described in [SECURITY.md](https://github.com/d3ltasecurity/markseal/blob/main/SECURITY.md).
