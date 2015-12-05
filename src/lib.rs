//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//

#![feature(custom_derive, custom_attribute, plugin)]
#![plugin(serde_macros)]
#![cfg_attr(test, allow(dead_code, unused_imports))]

#[allow(unused_imports)]
use std::io::prelude::*;

extern crate time;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate hyper;

header! { (OtxApiKey, "X-OTX-API-KEY") => [String] }
static OTX_DEFAULT_EXCHANGE: &'static str = "https://otx.alienvault.com";

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Indicator {
    #[serde(rename="_id")]
    pub id: String,
    pub created: String,
    pub indicator: String,
    #[serde(rename="type")]
    pub indicator_type: String,

    #[serde(default)]
    pub description: String,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Threat {
    pub id: String,

    pub author_name: String,
    pub name: String,

    #[serde(default)]
    pub description: String,
    pub created: String,
    pub modified: String,
    pub indicators: Vec<Indicator>,
    pub revision: f64,

    #[serde(default)]
    pub references: Vec<String>,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Threats {
    #[serde(default)]
    pub count: u64,

    #[serde(default)]
    pub next: Option<String>,

    #[serde(default)]
    pub previous: Option<String>,

    #[serde(default)]
    pub results: Vec<Threat>,
}

pub struct Client {
    apikey: Option<String>,
    client: hyper::Client,
    limit: Option<usize>,
    since: Option<time::Tm>,
    exchange: Option<String>,
}

impl Default for Client {
    fn default() -> Client {
        Client {
            limit: Some(25),
            since: Some(time::empty_tm()),
            exchange: Some(String::from(OTX_DEFAULT_EXCHANGE)),
            client: hyper::Client::new(),
            apikey: None,
        }
    }
}

impl Client {
    pub fn new() -> Client {
        Default::default()
    }

    pub fn limit<'a>(&'a mut self, val: usize) -> &'a mut Client {
        self.limit = Some(val);
        self
    }

    pub fn since<'a>(&'a mut self, t: time::Tm) -> &'a mut Client {
        self.since = Some(t);
        self
    }

    pub fn url<'a>(&'a mut self, location: &'a str) -> &'a mut Client {
        self.exchange = Some(String::from(location));
        self
    }

    pub fn apikey<'a>(&'a mut self, key: &'a str) -> &'a mut Client {
        self.apikey = Some(String::from(key));
        self
    }

    pub fn threats(&self, page: Option<String>) -> Option<Threats> {
        let url = match page {
            Some(loc) => loc,
            None => {
                format!("{}/api/v1/pulses/subscribed?limit={}&modified_since={}",
                        self.exchange.as_ref().unwrap(),
                        self.limit.unwrap(),
                        self.since.unwrap().rfc3339())
            }
        };

        let url = &url[..];
        let apikey = self.apikey.as_ref().expect("API key required!");
        let authorization = OtxApiKey(apikey.clone());

        match self.client.get(url).header(authorization).send() {
            Ok(mut r) => {
                if r.status != hyper::status::StatusCode::Ok {
                    return None;
                }
                let mut body = String::new();
                r.read_to_string(&mut body).unwrap();
                let data = &body[..];
                let result: Result<Threats, serde_json::error::Error> = serde_json::from_str(data);
                match result {
                    Ok(ts) => Some(ts),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }

    pub fn threat(&self, id: &str) -> Option<Threat> {
        let url = format!("{}/api/v1/pulses/{}", self.exchange.as_ref().unwrap(), id);
        let url = &url[..];

        let apikey = self.apikey.as_ref().expect("API key required!");
        let authorization = OtxApiKey(apikey.clone());
        match self.client.get(url).header(authorization).send() {
            Ok(mut r) => {
                let mut body = String::new();
                r.read_to_string(&mut body).unwrap();
                let data = &body[..];
                let val: Result<Threat, serde_json::error::Error> = serde_json::from_str(data);
                match val {
                    Ok(t) => Some(t),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }

    pub fn each<F>(&self, mut f: F)
        where F: FnMut(&Threat) -> bool
    {

        let mut pg: Option<String> = None;
        loop {

            let threats = self.threats(pg).unwrap();
            for threat in threats.results.iter() {
                if !f(threat) {
                    return;
                }
            }
            pg = threats.next;
            if pg.is_none() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::ops::*;
    use super::*;

    #[test]
    fn test_threats() {
        let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
        let mut otx = Client::new();
        let otx = otx.apikey(key).limit(2);
        let threats = otx.threats(None).unwrap();

        assert!(threats.results.len() == 2);
    }

    #[test]
    fn test_threats_since() {
        let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
        let now = time::now();
        let then = now.sub(time::Duration::days(1));
        let mut otx = Client::new();
        let otx = otx.apikey(key).since(then);
        let in_last_hour = otx.threats(None).unwrap();
        let otx = otx.since(time::empty_tm());
        let all_time = otx.threats(None).unwrap();

        assert!(all_time.count > in_last_hour.count);
    }

    #[test]
    fn test_each() {
        let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
        let mut otx = Client::new();
        let otx = otx.apikey(key).limit(2);
        let mut count = 5;
        otx.each(|_| {
            count -= 1;
            count > 0
        });
        assert!(count == 0);
    }
}
