namespace Moongazing.OrionVault.BlindIndex;

/// <summary>
/// Controls how a value is normalized before it is hashed into a blind index. Normalization
/// must be identical on the write path and the search path, otherwise equal logical values
/// would produce different indexes and search would miss. Because the chosen normalization is
/// baked into every stored index, changing it later is a re-index operation, not a
/// configuration tweak. The default (<see cref="TrimAndLowercaseInvariant"/>) suits
/// case-insensitive identifiers such as email addresses.
/// </summary>
public enum BlindIndexNormalization
{
    /// <summary>
    /// Trim leading and trailing whitespace, then lowercase using the invariant culture. Suits
    /// case-insensitive equality (emails, usernames). Invariant culture avoids the Turkish-i and
    /// other culture-specific casing surprises that would make indexes non-portable across hosts.
    /// </summary>
    TrimAndLowercaseInvariant = 0,

    /// <summary>Trim leading and trailing whitespace only; preserve case.</summary>
    Trim = 1,

    /// <summary>Hash the value exactly as supplied, with no normalization.</summary>
    None = 2,
}
