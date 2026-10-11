// Render the menu bar glyphs (deploy/icons/oarbank-{node,coordinator}-symbolic.svg) into the template PNGs the macOS
// apps load: <name>.png at 18x18 pixels and <name>@2x.png at 36x36, black on transparent (AppKit tints a template
// image for the menu bar's appearance). Run from the repository after changing an SVG:
//
//   xcrun swift scripts/render-menu-bar-icons.swift
//
// AppKit draws the SVG itself (NSImage reads SVG on macOS 14 and later), so nothing outside the Apple toolchain is
// needed.
import AppKit

let icons = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("deploy/icons")
for name in ["oarbank-node-symbolic", "oarbank-coordinator-symbolic"] {
    guard let image = NSImage(contentsOf: icons.appendingPathComponent("\(name).svg")) else {
        FileHandle.standardError.write(Data("cannot read \(name).svg\n".utf8)); exit(1)
    }
    for (scale, suffix) in [(1, ""), (2, "@2x")] {
        let pixels = 18 * scale
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                                         samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                         bytesPerRow: 0, bitsPerPixel: 0) else { exit(1) }
        rep.size = NSSize(width: 18, height: 18)            // points: the @2x file is the same image at twice the pixels
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        image.draw(in: NSRect(x: 0, y: 0, width: 18, height: 18))
        NSGraphicsContext.restoreGraphicsState()
        let out = icons.appendingPathComponent("\(name)\(suffix).png")
        try! rep.representation(using: .png, properties: [:])!.write(to: out)
        print(out.lastPathComponent)
    }
}
