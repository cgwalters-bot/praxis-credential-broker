//! List prices of the models the gateway serves, for what `/usage` says the
//! injected requests would have cost at API rates. The table is pinned here
//! and never fetched: a figure the board budgets against must not change
//! because a pricing page did. Update it, and `PRICES`, by hand.
use crate::runs::Usage;

/// The date the table was taken from the providers' pricing pages: Claude's
/// API pricing, OpenAI's API pricing (Standard tier, no data residency) and
/// Mistral's model pages.
pub(crate) const PRICES: &str = "2026-10-24";

/// USD per million tokens. Reasoning is billed as output everywhere, and
/// `Tokens::output` already includes it.
#[derive(Clone, Copy, Debug)]
struct Rates {
    input: f64,
    cache_read: f64,
    /// Anthropic's is its 5-minute rate, 1.25 times input: a write with the
    /// 1-hour TTL costs 2 times input, and is undercounted by a third.
    cache_write: f64,
    output: f64,
}

/// Rates for a model that has no separate cache-write price.
const fn plain(input: f64, cache_read: f64, output: f64) -> Rates {
    Rates {
        input,
        cache_read,
        cache_write: input,
        output,
    }
}

/// Anthropic's: writes at 1.25 times input.
const fn claude(input: f64, cache_read: f64, output: f64) -> Rates {
    Rates {
        input,
        cache_read,
        cache_write: input * 1.25,
        output,
    }
}

struct Price {
    /// As upstream names the model in its response, without a snapshot
    /// date (see [`undated`]).
    model: &'static str,
    rates: Rates,
    /// The rates for a whole request whose prompt, cached or not, is longer
    /// than this many tokens.
    long: Option<(u64, Rates)>,
}

const fn price(model: &'static str, rates: Rates) -> Price {
    Price {
        model,
        rates,
        long: None,
    }
}

/// OpenAI bills a prompt over 272K tokens at twice the input and cache
/// rates and 1.5 times output.
const fn openai(model: &'static str, input: f64, cache_read: f64, output: f64) -> Price {
    Price {
        model,
        rates: plain(input, cache_read, output),
        long: Some((272_000, plain(input * 2.0, cache_read * 2.0, output * 1.5))),
    }
}

const TABLE: &[Price] = &[
    price("claude-fable-5-1", claude(10.0, 0.25, 50.0)),
    price("claude-fable-5", claude(10.0, 1.0, 50.0)),
    price("claude-opus-5-5", claude(4.0, 0.2, 20.0)),
    price("claude-opus-5", claude(5.0, 0.5, 25.0)),
    price("claude-opus-4-8", claude(5.0, 0.5, 25.0)),
    price("claude-opus-4-7", claude(5.0, 0.5, 25.0)),
    price("claude-opus-4-6", claude(5.0, 0.5, 25.0)),
    price("claude-sonnet-5-5", claude(2.0, 0.2, 10.0)),
    price("claude-sonnet-5", claude(2.0, 0.2, 10.0)),
    price("claude-sonnet-4-6", claude(3.0, 0.3, 15.0)),
    Price {
        model: "claude-haiku-5-5",
        rates: claude(0.1, 0.01, 0.5),
        long: Some((100_000, claude(0.5, 0.05, 2.5))),
    },
    price("claude-haiku-4-5", claude(1.0, 0.1, 5.0)),
    // The Responses API reports cache writes, at their own rate.
    Price {
        model: "gpt-6.1-sol",
        rates: Rates {
            cache_write: 2.5,
            ..plain(2.0, 0.1, 10.0)
        },
        long: Some((
            272_000,
            Rates {
                cache_write: 5.0,
                ..plain(4.0, 0.2, 15.0)
            },
        )),
    },
    openai("gpt-6-sol", 2.0, 0.2, 10.0),
    openai("gpt-6-astra", 10.0, 1.0, 50.0),
    openai("gpt-6-luna", 0.1, 0.01, 0.5),
    price("gpt-5.3-codex", plain(1.75, 0.175, 14.0)),
    price("zai-glm-5-3", plain(1.4, 0.14, 4.4)),
];

/// `model` without a trailing snapshot date, `-YYYYMMDD` as Anthropic dates
/// its models or `-YYYY-MM-DD` as OpenAI does, or None if it has none. A
/// snapshot is priced as its alias is.
fn undated(model: &str) -> Option<&str> {
    let date = |len: usize, dashes: &[usize]| {
        let start = model.len().checked_sub(len + 1)?;
        let suffix = &model.as_bytes()[start..];
        let well_formed = suffix[0] == b'-'
            && suffix[1..].iter().enumerate().all(|(i, b)| {
                if dashes.contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            });
        // The suffix is ASCII, so `start` is a character boundary.
        well_formed.then(|| &model[..start])
    };
    date(8, &[]).or_else(|| date(10, &[4, 7]))
}

/// What a response would have cost at list price, in millionths of a USD,
/// or None if the table has no price for the model it names, or it names
/// none.
pub(crate) fn cost(usage: &Usage) -> Option<u64> {
    let model = usage.model.as_deref()?;
    let find = |model: &str| TABLE.iter().find(|price| price.model == model);
    let price = find(model).or_else(|| find(undated(model)?))?;
    let tokens = &usage.tokens;
    let prompt = tokens.input.saturating_add(tokens.cache_read);
    let rates = match price.long {
        Some((above, long)) if prompt > above => long,
        _ => price.rates,
    };
    // `input` is the uncached part, cache writes included.
    let cache_write = usage.cache_write.min(tokens.input);
    // Rates are per million tokens, so this is in millionths of a USD. The
    // cast back saturates.
    let micros = (tokens.input - cache_write) as f64 * rates.input
        + cache_write as f64 * rates.cache_write
        + tokens.cache_read as f64 * rates.cache_read
        + tokens.output as f64 * rates.output;
    Some(micros.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runs::Tokens;

    fn usage(model: &str, input: u64, cache_read: u64, cache_write: u64, output: u64) -> Usage {
        Usage {
            tokens: Tokens {
                input,
                cache_read,
                output,
                total: input + cache_read + output,
                ..Tokens::default()
            },
            model: Some(model.to_owned()),
            cache_write,
        }
    }

    #[test]
    fn every_model_is_priced_once_with_rates_in_order() {
        for (i, price) in TABLE.iter().enumerate() {
            assert!(
                TABLE[..i].iter().all(|other| other.model != price.model),
                "{}",
                price.model
            );
            for rates in std::iter::once(price.rates).chain(price.long.map(|(_, r)| r)) {
                assert!(rates.cache_read < rates.input, "{}", price.model);
                assert!(rates.cache_write >= rates.input, "{}", price.model);
                assert!(rates.output > rates.input, "{}", price.model);
            }
        }
    }

    /// The usage of the Responses stream recorded in testdata: 16 input,
    /// none cached, 5 output.
    #[test]
    fn a_recorded_codex_response_costs_its_list_price() {
        // 16 * $2 + 5 * $10 per million.
        assert_eq!(cost(&usage("gpt-6.1-sol", 16, 0, 0, 5)), Some(82));
        // Writes and reads at their own rates: 1000 * 2 + 1000 * 2.5 + 2000
        // * 0.1 + 10 * 10.
        assert_eq!(
            cost(&usage("gpt-6.1-sol", 2000, 2000, 1000, 10)),
            Some(4800)
        );
        // Over 272K the whole request is at the long rates.
        assert_eq!(
            cost(&usage("gpt-6.1-sol", 200_000, 100_000, 0, 1000)),
            Some(800_000 + 20_000 + 15_000)
        );
    }

    /// An Anthropic response's usage, as `token_count` records it: input
    /// counts every class, of which `cache_read` and `cache_write` are
    /// parts.
    #[test]
    fn a_claude_response_costs_its_list_price() {
        // 6050 input of which 5000 cache reads and 1000 writes, 100 output:
        // 50 * 4 + 1000 * 5 + 5000 * 0.2 + 100 * 20.
        assert_eq!(
            cost(&usage("claude-opus-5-5", 1050, 5000, 1000, 100)),
            Some(8200)
        );
        assert_eq!(
            cost(&usage("claude-haiku-5-5", 100_001, 0, 0, 0)),
            Some(50_001)
        );
        // A reported write larger than the uncached input is capped by it.
        assert_eq!(cost(&usage("claude-opus-5-5", 10, 0, 50, 0)), Some(50));
    }

    #[test]
    fn a_snapshot_is_priced_as_its_alias() {
        assert_eq!(
            cost(&usage("claude-haiku-4-5-20251001", 1_000_000, 0, 0, 0)),
            Some(1_000_000)
        );
        assert_eq!(
            cost(&usage("gpt-6.1-sol-2026-09-29", 16, 0, 0, 5)),
            Some(82)
        );
        assert_eq!(undated("gpt-6.1-sol"), None);
        assert_eq!(undated("claude-opus-4-6"), None);
    }

    #[test]
    fn an_unknown_or_unnamed_model_is_unpriced() {
        assert_eq!(cost(&usage("claude-test", 1, 0, 0, 1)), None);
        // A prefixed name, or a suffix that is not a date, is another model.
        assert_eq!(cost(&usage("us.claude-haiku-4-5", 1, 0, 0, 1)), None);
        assert_eq!(cost(&usage("gpt-6.1-sol-2026-0929", 1, 0, 0, 1)), None);
        assert_eq!(cost(&usage("claude-haiku-4-5-2025100", 1, 0, 0, 1)), None);
        assert_eq!(cost(&usage("claude-haiku-4-5-2025100x", 1, 0, 0, 1)), None);
        assert_eq!(cost(&usage("-20251001", 1, 0, 0, 1)), None);
        let mut unnamed = usage("gpt-6.1-sol", 1, 0, 0, 1);
        unnamed.model = None;
        assert_eq!(cost(&unnamed), None);
        assert_eq!(cost(&usage("gpt-6.1-sol", 0, 0, 0, 0)), Some(0));
    }
}
