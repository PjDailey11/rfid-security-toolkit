"""Documented risks for Wiegand credential observations."""

WIEGAND_26_KEYSPACE_FACILITY_BITS = 12
WIEGAND_26_KEYSPACE_CARD_BITS = 12

# Facility and card fields are effectively public once observed on the wire.
WIEGAND_EFFECTIVE_CARD_SEARCH_SPACE = 1 << WIEGAND_26_KEYSPACE_CARD_BITS  # 4096 per facility
WIEGAND_EFFECTIVE_FACILITY_SEARCH_SPACE = 1 << WIEGAND_26_KEYSPACE_FACILITY_BITS  # 4096


def brute_force_card_note(facility_known: bool = True) -> str:
    """Human-readable note on brute-force feasibility for the card number field."""
    if facility_known:
        return (
            f"With facility code known, card number is only {WIEGAND_EFFECTIVE_CARD_SEARCH_SPACE:,} "
            "candidates (12 bits). An attacker who can transmit crafted Wiegand frames can iterate "
            "this space quickly in software."
        )
    return (
        f"Joint brute force over facility ({WIEGAND_EFFECTIVE_FACILITY_SEARCH_SPACE:,}) × "
        f"card ({WIEGAND_EFFECTIVE_CARD_SEARCH_SPACE:,}) is ~16.7M combinations for naive "
        "enumeration of both 12-bit fields (parity must remain valid per field grouping)."
    )


REPLAY_RISK = (
    "Wiegand has no per-timestamp, MAC, or rolling code at the physical layer. "
    "A captured bit sequence can typically be replayed verbatim unless upstream panels "
    "implement anti-replay (uncommon on legacy readers)."
)


CLONING_AND_RELAY = (
    "Credential cloning (encode observed bits onto another transmitter) and relay attacks "
    "(extend logical proximity via RF bridge) are practical against many legacy deployments. "
    "Mitigate with OSDP Secure Channel, cryptographically bound credentials, and MFA."
)
