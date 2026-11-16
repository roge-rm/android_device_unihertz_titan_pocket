// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/** Backend for an appropriately authorized service; no privilege escalation. */
public final class KeyboardLightWriter {
    private final Path directory;
    public KeyboardLightWriter() { this(Paths.get("/sys/class/leds/button-backlight")); }
    // Package-private injectable directory is used by host fixtures, never user configuration.
    KeyboardLightWriter(Path directory) { this.directory = directory; }
    public void set(boolean on) throws IOException {
        final int maximum;
        try {
            maximum = Integer.parseInt(new String(Files.readAllBytes(directory.resolve("max_brightness")), StandardCharsets.US_ASCII).trim());
        } catch (NumberFormatException e) {
            throw new IOException("Invalid keyboard LED range", e);
        }
        if (maximum < 1 || maximum > 65535) throw new IOException("Unsupported keyboard LED range");
        Files.write(directory.resolve("brightness"), Integer.toString(on ? maximum : 0).getBytes(StandardCharsets.US_ASCII), StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
