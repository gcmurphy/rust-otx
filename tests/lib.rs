extern crate otx;
extern crate time;

use std::env;
use std::ops::Sub;

#[test]
fn test_all_threats() {
    let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
    let mut otx = otx::Client::new();
    let otx = otx.apikey(key).limit(2);
    let threats = otx.threats(None).unwrap();
    assert!(threats.results.len() == 2);
}

#[test]
fn test_threats_since() {

    let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
    let now = time::now();
    let then = now.sub(time::Duration::days(1));
    let mut otx = otx::Client::new();
    let otx = otx.apikey(key).since(then);
    let in_last_hour = otx.threats(None).unwrap();
    let otx = otx.since(time::empty_tm());
    let all_time = otx.threats(None).unwrap();

    assert!(all_time.count > in_last_hour.count);
}

#[test]
fn test_each() {
    let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
    let mut otx = otx::Client::new();
    let otx = otx.apikey(key).limit(2);
    let mut count = 5;
    otx.each(|_| {
        count -= 1;
        count > 0
    });
    assert!(count == 0);
}
