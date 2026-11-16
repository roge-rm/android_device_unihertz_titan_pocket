# SPDX-License-Identifier: Apache-2.0
# The touchpad under the keyboard (input device mtk-pad).
#
# Stock sets touch.deviceType = touchPad, which Android 16 no longer has.
# As a touch screen bound to a display ID that doesn't exist, the touch
# mapper stays disabled: the pad is read but sends nothing to apps, as on
# stock with keyboard swiping off. touchNavigation ignores touch.displayId
# and would turn taps and flings into DPAD keys. Swipe scrolling needs its
# own reader of the raw events, see TOUCHPAD_PORT.md.
touch.deviceType = touchScreen
touch.displayId = mtk-pad-unbound
touch.orientationAware = 1
