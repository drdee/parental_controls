#!/bin/bash
#
# Records a narrated walkthrough of the app in preview mode.
#
# Drives the wizard with AppleScript on timed beats while ffmpeg captures the
# screen, then composites explanatory captions at known timestamps. Preview
# mode means nothing on this Mac is modified.
#
# Needs Screen Recording permission for the terminal running it. Without it
# ffmpeg hangs rather than failing, so check first with:
#   screencapture -x /tmp/x.png && echo OK
#
# Usage: tools/record-preview-demo.sh [output.mov]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$REPO/ParentalControls/build/Family-Safety.app"
OUT="${1:-$REPO/build/family-safety-preview.mov}"
WORK="$(mktemp -d)"
RAW="$WORK/raw.mov"

trap 'rm -rf "$WORK"' EXIT

[ -d "$APP" ] || { echo "error: no app at $APP -- build it first" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"

# Beat timings in seconds from the start of capture. Captions and clicks are
# driven from these same numbers so they cannot drift apart.
T_INTRO=6
T_MODE=11
T_CONFIGURE=20
T_REVIEW=30
T_RUNNING=38
T_RESULTS=46
T_END=54

echo "Recording to $OUT"
echo "Do not touch the keyboard or mouse for about ${T_END}s."

# Terminate any previous instance. `tell app ... to quit` is unreliable here --
# it silently fails and leaves the process running, which then means `open -a`
# below re-focuses a window sitting at the END of the wizard instead of
# starting fresh, and the whole recording captures the results screen.
quit_app() {
    pkill -f "Family-Safety.app/Contents/MacOS/ParentalControls" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        pgrep -f "Family-Safety.app/Contents/MacOS/ParentalControls" >/dev/null || return 0
        sleep 1
    done
    echo "warning: could not terminate a running instance" >&2
}

# The window is placed at a known origin so the crop is deterministic rather
# than wherever macOS last left it.
WIN_X=200
WIN_Y=160

quit_app
sleep 1

open -a "$APP"
sleep 3

# Move the window first, then read back where it ACTUALLY is. Setting a
# position is a request, not a guarantee -- macOS clamps it to the visible
# frame, and a previous run of this script recorded nothing but wallpaper
# because the crop used the requested origin rather than the real one.
osascript -e "tell application \"System Events\" to tell process \"ParentalControls\" to set position of window 1 to {$WIN_X, $WIN_Y}" >/dev/null 2>&1 || true
sleep 1
read -r WIN_X WIN_Y <<<"$(osascript -e 'tell application "System Events" to tell process "ParentalControls" to return position of window 1' 2>/dev/null | tr ',' ' ')"
read -r WIN_W WIN_H <<<"$(osascript -e 'tell application "System Events" to tell process "ParentalControls" to return size of window 1' 2>/dev/null | tr ',' ' ')"
WIN_X=${WIN_X:-200}
WIN_Y=${WIN_Y:-160}
WIN_W=${WIN_W:-900}
WIN_H=${WIN_H:-592}
echo "Window at ${WIN_X},${WIN_Y} size ${WIN_W}x${WIN_H} (points)"

# Record the window rect directly with screencapture rather than grabbing the
# whole screen and cropping in ffmpeg.
#
# ffmpeg's avfoundation device does not capture at the panel resolution: on
# this 3456x2234 Retina display (1728 points) it produced 1920x1440, a
# different aspect ratio again, so no integer scale factor relates window
# points to captured pixels and a computed crop lands on empty wallpaper.
# `screencapture -R` takes the rect in points and does the mapping itself.
MARGIN_PT=2
REC_X=$(( WIN_X - MARGIN_PT )); [ "$REC_X" -lt 0 ] && REC_X=0
REC_Y=$(( WIN_Y - MARGIN_PT )); [ "$REC_Y" -lt 0 ] && REC_Y=0
REC_W=$(( WIN_W + MARGIN_PT * 2 ))
REC_H=$(( WIN_H + MARGIN_PT * 2 ))

screencapture -v -k -R"${REC_X},${REC_Y},${REC_W},${REC_H}" -V "$T_END" "$RAW" &
CAPTURE_PID=$!
sleep 2

# The process is "ParentalControls" (the executable), not "Family-Safety" (the
# bundle). Its SwiftUI buttons expose no accessibility title -- they read back
# as `missing value` -- so they cannot be clicked by name. The primary button
# on each screen carries .keyboardShortcut(.defaultAction), so Return
# activates it, which is also less brittle than clicking by index.
osascript <<APPLESCRIPT || true
tell application "System Events"
    tell process "ParentalControls"
        set frontmost to true
        delay 2
        try
            click checkbox "Preview only — don't change anything" of group 1 of window 1
        end try
        delay $((T_MODE - 7))
        keystroke return
        delay $((T_CONFIGURE - T_MODE))
        keystroke return
        delay $((T_REVIEW - T_CONFIGURE))
        keystroke return
    end tell
end tell
APPLESCRIPT

wait $CAPTURE_PID || true
[ -s "$RAW" ] || { echo "error: capture produced nothing" >&2; exit 1; }

# Already cropped to the window by screencapture -R, so the only thing left is
# to size the captions to whatever it produced.
WIDTH=$(ffprobe -v error -select_streams v:0 -show_entries stream=width -of csv=p=0 "$RAW")
echo "Captured ${WIDTH}px wide. Compositing captions..."

# Captions are rendered as PNGs and composited with `overlay`, because
# Homebrew's ffmpeg is built without libfreetype and so has no `drawtext`.
caption_index=0
INPUTS=()
FILTER=""
PREV="[0:v]"

add_caption() {   # add_caption <start> <end> <heading> <detail>
    local start=$1 end=$2 heading=$3 detail=$4
    local png="$WORK/cap-$caption_index.png"
    python3 "$REPO/tools/make-caption.py" "$WIDTH" "$png" "$heading" "$detail" >/dev/null
    INPUTS+=(-i "$png")
    local input=$((caption_index + 1))
    local next="[v$input]"
    # Centred over the lower third: low enough not to hide the screen's
    # heading, high enough to clear the footer buttons being described.
    FILTER+="${PREV}[${input}:v]overlay=x=(W-w)/2:y=H-h-24:enable='between(t,${start},${end})'${next};"
    PREV="$next"
    caption_index=$((caption_index + 1))
}

# Four screens, not five: in Family mode the wizard goes
# Mode -> Review -> Running -> Results, with no separate configure step.
# Labelling them 1..5 put every middle caption a stage out of step with the
# screen behind it.
add_caption 1 $T_INTRO "Family Safety Setup — Preview Mode" \
    "A walkthrough that changes nothing on this Mac"
add_caption $T_INTRO $T_MODE "Step 1 of 4 — Choose a mode" \
    "Family Mode is content filtering only, and fully reversible"
add_caption $T_MODE $T_CONFIGURE "Preview only is switched on" \
    "Nothing is written, no profile saved, no account created"
add_caption $T_CONFIGURE $T_REVIEW "Step 2 of 4 — Review every change first" \
    "Each card says what changes, and how to undo it"
add_caption $T_REVIEW $T_RUNNING "8 changes, none touching accounts or FileVault" \
    "DNS filtering, a configuration profile, browser policy"
add_caption $T_RUNNING $T_RESULTS "Step 3 of 4 — Applying (simulated here)" \
    "A real run asks for an administrator password once"
add_caption $T_RESULTS $T_END "Step 4 of 4 — Results" \
    "Undo All Changes reverses it; Reveal Log saves diagnostics"

# yuv420p is set here -- on the output, where it is supported -- because
# QuickTime will not play the capture device's native format. Width is forced
# even; H.264 rejects odd dimensions and the crop margin can produce one.
FILTER+="${PREV}scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p[out]"

ffmpeg -hide_banner -loglevel error -i "$RAW" "${INPUTS[@]}" \
    -filter_complex "$FILTER" -map "[out]" \
    -c:v libx264 -preset medium -crf 22 -movflags +faststart \
    "$OUT" -y

echo "Wrote $OUT"
