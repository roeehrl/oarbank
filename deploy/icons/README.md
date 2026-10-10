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

# Menu bar glyphs

The macOS menu bar items use template images: black on transparent, which AppKit tints for the menu bar's appearance
(light, dark, tinted, selected). Two glyphs of one family, so a Mac that runs both apps can tell them apart at a
glance (and never shows both: see docs/design/node-enrollment.md, "Menu bar and tray"):

| Glyph | App | Drawing |
|---|---|---|
| `oarbank-node-symbolic` | Oarbank Node | one oar, blade in the water: this one machine |
| `oarbank-coordinator-symbolic` | Oarbank Coordinator | three oars pulling together: the fleet (the logo's bank of oars) |

The SVGs (18 × 18 points, `currentColor`) are the source. `xcrun swift scripts/render-menu-bar-icons.swift` renders each
to `<name>.png` (18 × 18 pixels) and `<name>@2x.png` (36 × 36); the packages copy both pairs into the app's
resources, and `NSImage(named:)` picks the resolution for the display. Rendering is deterministic: commit the PNGs
with the SVG they come from.
