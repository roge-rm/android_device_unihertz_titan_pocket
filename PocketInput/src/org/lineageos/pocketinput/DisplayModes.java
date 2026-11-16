// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

/**
 * Display modes (mini mode, MINI_MODE_CONTRACT.md), shared by the settings app and
 * PocketDisplayMode in system_server. Each mode forces a logical size and density on the
 * default display; the panel stays 720x720 at its normal density (ro.sf.lcd_density).
 */
public final class DisplayModes {
    /** Settings.Global: the active mode ID, NORMAL when off. The app, tile and key combo write it. */
    public static final String SETTING = "pocket_display_mode";
    /** Settings.Global: the mode the Quick Settings tile turns on. */
    public static final String CHOICE_SETTING = "pocket_display_mode_choice";
    /** Settings.Global: the custom mode as "width height density", used when the ID is CUSTOM. */
    public static final String CUSTOM_SETTING = "pocket_display_mode_custom";
    /**
     * Settings.Global: the last kept mode, as keptValue writes it, applied at boot when
     * DisplayModeBoot.SETTING is 1. Written by PocketDisplayMode only.
     */
    public static final String KEPT_SETTING = "pocket_display_mode_kept";
    public static final String NORMAL = "normal";
    public static final String CUSTOM = "custom";
    public static final String PORTRAIT_MINI = "portrait_mini";
    public static final String DEFAULT_CHOICE = "square_698_1440";

    /** Square content sizes across, in dp, and render sizes in px. */
    public static final int[] SQUARE_DP = {470, 580, 698, 820};
    public static final int[] SQUARE_RENDER = {720, 1080, 1440};

    /** Custom limits: width and height in px, the narrow side in dp, density in dpi. */
    public static final int CUSTOM_MIN_SIZE = 360, CUSTOM_MAX_SIZE = 2160;
    public static final int CUSTOM_MIN_DP = 320;
    public static final int CUSTOM_MIN_DENSITY = 100, CUSTOM_MAX_DENSITY = 640;

    public static final class Mode {
        public final String id;
        public final String label;
        public final int width, height, density;

        Mode(String id, String label, int width, int height, int density) {
            this.id = id;
            this.label = label;
            this.width = width;
            this.height = height;
            this.density = density;
        }

        /** Width in dp, rounded. */
        public int widthDp() {
            return Math.round(width * 160f / density);
        }

        /** Height in dp, rounded. */
        public int heightDp() {
            return Math.round(height * 160f / density);
        }

        @Override public String toString() {
            return id + " " + width + "x" + height + " at " + density;
        }
    }

    /** Every fixed mode: stock's portrait profile, then the square table by content, then render. */
    public static final Mode[] MODES = buildModes();

    /** Old IDs from the first three square modes, all 698 dp. */
    private static final String[][] ALIASES = {
        {"square_1440", "square_698_1440"},
        {"square_1080", "square_698_1080"},
        {"square_720", "square_698_720"},
    };

    private DisplayModes() {}

    private static Mode[] buildModes() {
        Mode[] modes = new Mode[1 + SQUARE_DP.length * SQUARE_RENDER.length];
        modes[0] = new Mode(PORTRAIT_MINI, "Portrait mini", 432, 720, 160);
        int i = 1;
        for (int dp : SQUARE_DP) {
            for (int render : SQUARE_RENDER) {
                modes[i++] = new Mode(squareId(dp, render),
                        "Square " + dp + " dp, " + render + "x" + render,
                        render, render, squareDensity(dp, render));
            }
        }
        return modes;
    }

    /** "square_<dp>_<render>". */
    public static String squareId(int dp, int render) {
        return "square_" + dp + "_" + render;
    }

    /** Density for a square mode: render x 160 / dp, rounded. */
    public static int squareDensity(int dp, int render) {
        return Math.round(render * 160f / dp);
    }

    /** The fixed mode with this ID (old IDs too), or null for NORMAL, CUSTOM, null or unknown IDs. */
    public static Mode find(String id) {
        if (id == null) return null;
        for (String[] alias : ALIASES) if (alias[0].equals(id)) id = alias[1];
        for (Mode mode : MODES) if (mode.id.equals(id)) return mode;
        return null;
    }

    /**
     * The mode for the settings: a fixed mode, the custom mode from its value, or null for
     * normal. Unknown IDs and a bad custom value are normal.
     */
    public static Mode resolve(String id, String custom) {
        return CUSTOM.equals(id) ? custom(custom) : find(id);
    }

    /** The tile's mode: the saved choice, or the default when it's missing, unknown or bad. */
    public static Mode choice(String id, String custom) {
        Mode mode = resolve(id, custom);
        return mode != null ? mode : find(DEFAULT_CHOICE);
    }

    /** The custom mode from "width height density", or null when it's malformed or refused. */
    public static Mode custom(String value) {
        if (value == null) return null;
        String[] parts = value.trim().split("\\s+");
        if (parts.length != 3) return null;
        int width, height, density;
        try {
            width = Integer.parseInt(parts[0]);
            height = Integer.parseInt(parts[1]);
            density = Integer.parseInt(parts[2]);
        } catch (NumberFormatException e) {
            return null;
        }
        return custom(width, height, density);
    }

    /** The custom mode, or null when customError refuses it. */
    public static Mode custom(int width, int height, int density) {
        if (customError(width, height, density) != null) return null;
        return new Mode(CUSTOM, "Custom " + width + "x" + height + " at " + density,
                width, height, density);
    }

    /** Why a custom mode is refused, or null when it's fine. */
    public static String customError(int width, int height, int density) {
        if (width < CUSTOM_MIN_SIZE || width > CUSTOM_MAX_SIZE
                || height < CUSTOM_MIN_SIZE || height > CUSTOM_MAX_SIZE) {
            return "Width and height must be " + CUSTOM_MIN_SIZE + " to " + CUSTOM_MAX_SIZE;
        }
        if (density < CUSTOM_MIN_DENSITY || density > CUSTOM_MAX_DENSITY) {
            return "Density must be " + CUSTOM_MIN_DENSITY + " to " + CUSTOM_MAX_DENSITY;
        }
        if (Math.round(Math.min(width, height) * 160f / density) < CUSTOM_MIN_DP) {
            return "The narrow side must be at least " + CUSTOM_MIN_DP + " dp";
        }
        return null;
    }

    /** The custom setting's value for a mode: "width height density". */
    public static String customValue(Mode mode) {
        return mode.width + " " + mode.height + " " + mode.density;
    }

    /** KEPT_SETTING's value: NORMAL, a fixed mode's ID, or "custom width height density". */
    public static String keptValue(Mode mode) {
        if (mode == null) return NORMAL;
        return CUSTOM.equals(mode.id) ? CUSTOM + " " + customValue(mode) : mode.id;
    }

    /** The mode from KEPT_SETTING's value, null for normal, missing or bad values. */
    public static Mode kept(String value) {
        if (value == null) return null;
        String prefix = CUSTOM + " ";
        return value.startsWith(prefix) ? custom(value.substring(prefix.length())) : find(value);
    }

    /** Same size and density, null being normal. IDs don't count. */
    public static boolean same(Mode a, Mode b) {
        if (a == null || b == null) return a == b;
        return a.width == b.width && a.height == b.height && a.density == b.density;
    }
}
