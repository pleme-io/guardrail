use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::ChangeWindow;

#[must_use]
pub fn parse_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let (yy, mm) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3_600 + mi * 60 + se)
}

#[must_use]
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[must_use]
pub fn open_window<'a>(
    windows: &'a [ChangeWindow],
    tag: &str,
    now: i64,
) -> Option<&'a ChangeWindow> {
    windows.iter().filter(|w| w.tag == tag).find(|w| {
        matches!((parse_utc(&w.start), parse_utc(&w.end)), (Some(s), Some(e)) if s <= now && now < e)
    })
}

#[must_use]
pub fn invalid(windows: &[ChangeWindow]) -> Vec<&ChangeWindow> {
    windows
        .iter()
        .filter(|w| match (parse_utc(&w.start), parse_utc(&w.end)) {
            (Some(s), Some(e)) => s >= e,
            _ => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(tag: &str, start: &str, end: &str) -> ChangeWindow {
        ChangeWindow {
            name: "oct-11".into(),
            tag: tag.into(),
            start: start.into(),
            end: end.into(),
        }
    }

    #[test]
    fn parses_utc_against_known_epochs() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2026-10-11T06:00:00Z"), Some(1_791_698_400));
        assert_eq!(parse_utc("2000-02-29T12:00:00Z"), Some(951_825_600));
    }

    #[test]
    fn refuses_anything_but_utc_z() {
        for s in [
            "2026-10-11T06:00:00+02:00",
            "2026-10-11 06:00:00Z",
            "2026-13-01T00:00:00Z",
            "soon",
            "",
        ] {
            assert_eq!(parse_utc(s), None, "{s}");
        }
    }

    #[test]
    fn open_only_inside_a_window_with_the_tag() {
        let ws = [w(
            "akeyless-production",
            "2026-10-11T06:00:00Z",
            "2026-10-11T18:00:00Z",
        )];
        let at = |s: &str| parse_utc(s).unwrap();
        assert!(open_window(&ws, "akeyless-production", at("2026-10-11T06:00:00Z")).is_some());
        assert!(open_window(&ws, "akeyless-production", at("2026-10-11T17:59:59Z")).is_some());
        assert!(open_window(&ws, "akeyless-production", at("2026-10-11T18:00:00Z")).is_none());
        assert!(open_window(&ws, "akeyless-production", at("2026-10-11T05:59:59Z")).is_none());
        assert!(open_window(&ws, "other", at("2026-10-11T12:00:00Z")).is_none());
    }

    #[test]
    fn an_unparseable_or_inverted_window_never_opens_and_is_reported() {
        let ws = [
            w("t", "2026-10-11T18:00:00Z", "2026-10-11T06:00:00Z"),
            w("t", "tomorrow", "2026-10-12T00:00:00Z"),
        ];
        assert!(open_window(&ws, "t", parse_utc("2026-10-11T12:00:00Z").unwrap()).is_none());
        assert_eq!(invalid(&ws).len(), 2);
    }
}
