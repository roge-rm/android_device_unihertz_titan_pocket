// SPDX-License-Identifier: GPL-2.0-only
#ifndef TPDIAG_COMMANDS_H
#define TPDIAG_COMMANDS_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

enum tpdiag_command { TPDIAG_NONE, TPDIAG_REBOOT, TPDIAG_BOOTLOADER };
struct tpdiag_parser { char line[32]; size_t size; bool overflow; };

static inline enum tpdiag_command tpdiag_feed(struct tpdiag_parser *parser, char byte)
{
    enum tpdiag_command result = TPDIAG_NONE;
    if (byte == '\n') {
        if (!parser->overflow) {
            if (parser->size && parser->line[parser->size - 1] == '\r') parser->size--;
            parser->line[parser->size] = 0;
            if (!strcmp(parser->line, "reboot")) result = TPDIAG_REBOOT;
            else if (!strcmp(parser->line, "reboot-bootloader")) result = TPDIAG_BOOTLOADER;
        }
        parser->size = 0;
        parser->overflow = false;
    } else if (byte == '\0' || parser->size == sizeof(parser->line) - 1) {
        parser->overflow = true;
    } else if (!parser->overflow) {
        parser->line[parser->size++] = byte;
    }
    return result;
}
#endif
