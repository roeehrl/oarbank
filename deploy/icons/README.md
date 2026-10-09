# Coordinator application icons

These are native conversions of the official `docs/assets/logo.svg`, not a new logo.
Linux packages install that SVG directly in the hicolor theme. macOS packages include
`oarbank.icns` as a signed bundle resource; Windows embeds `oarbank.ico` for both the
Start menu shortcut and Installed Apps.

To regenerate, render the SVG with Sharp (density 384) at 16, 32, 128, 256 and
512 pixels, plus each size at twice the resolution, into a macOS `.iconset`
directory using the standard `icon_<size>x<size>[@2x].png` filenames. Run
`iconutil -c icns <directory> -o deploy/icons/oarbank.icns`.
Render a 1024-pixel PNG from the same SVG and save with Pillow as ICO using
sizes 16, 24, 32, 48, 64, 128 and 256. These conversions preserve transparency.
