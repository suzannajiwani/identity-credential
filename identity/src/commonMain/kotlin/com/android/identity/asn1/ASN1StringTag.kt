package com.android.identity.asn1

enum class ASN1StringTag(val tag: Int) {
    UTF8_STRING(0x0c),
    NUMERIC_STRING(0x12),
    PRINTABLE_STRING(0x13),
    TELETEX_STRING(0x14),
    VIDEOTEX_STRING(0x15),
    IA5_STRING(0x16),
    GRAPHIC_STRING(0x19),
    VISIBLE_STRING(0x1a),
    GENERAL_STRING(0x1b),
    UNIVERSAL_STRING(0x1c),
    CHARACTER_STRING(0x1d),
    BMP_STRING(0x1e)
}