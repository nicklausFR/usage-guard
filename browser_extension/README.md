# Usage Guard Browser Bridge

The Windows installer copies this directory to
`C:\Program Files\Usage Guard\Browser Extension\current`. In Brave, open
`brave://extensions`, enable **Developer mode**, choose **Load unpacked**, and
select that directory. Extensions are enabled separately for each browser
profile.

The extension contacts only `127.0.0.1:8765`, where the local Usage Guard
bridge listens. It reports the active tab URL, title, and playback state, then
receives the website and category limits calculated by the Windows client. Its
banner and blocking overlay affect only the relevant page.

The **Options** page can show the banner permanently, during the warning
period, or at regular intervals. It also controls its position and background
opacity. Once a limit has expired, the banner remains visible regardless of
that display preference.

Reported addresses include the path, for example
`usage.example.com/usage-guard`. Query parameters and fragments are discarded.

To apply the same limits in private windows, explicitly allow the extension in
private mode from the extension details page. Automatic detection and guidance
for that browser setting are not implemented yet.
