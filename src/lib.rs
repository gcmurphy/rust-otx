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

use std::fmt;
use std::str::FromStr;

header! { (OtxApiKey, "X-OTX-API-KEY") => [String] }
static OTX_DEFAULT_EXCHANGE: &'static str = "https://otx.alienvault.com";

#[derive(Debug, Clone, PartialEq)]
pub enum IndicatorType {

    /// An IPv4 address indicating the online location of a server
    /// or other computer.
    IPv4,

    /// An IPv6 address indicating the online location of a server
    /// or other computer.
    IPv6,

    /// A domain name for a website or server. Domains encompass a
    /// series of hostnames.
    Domain,

    /// The hostname for a server located within a domain.
    Hostname,

    /// An email associated with suspicious activity.
    Email,

    /// Uniform Resource Location (URL) summarizing the online location of a
    /// file or resource.
    URL,

    /// Uniform Resource Indicator (URI) describing the explicit path to a
    /// file hosted online.
    URI,

    /// A MD5-format hash that summarizes the architecture and content
    /// of a file.
    MD5,

    /// A SHA-format hash that summarizes the architecture and content
    /// of a file.
    SHA1,

    /// A SHA-256-format hash that summarizes the architecture and content
    /// of a file.
    SHA256,

    /// A PEPHASH-format hash that summarizes the architecture and content
    /// of a file.
    PEHASH,

    /// An IMPHASH-format hash that summarizes the architecture and
    /// content of a file.
    IMPHASH,

    /// Classless Inter-Domain Routing (CIDR) address, which describes
    /// both a server's IP address and the network architecture (routing path)
    /// surrounding that server.
    CIDR,

    /// A unique location in a file system.
    FilePath,

    /// The name of a mutex resource describing the execution
    /// architecture of a file.
    Mutex,

    /// Common Vulnerability and Exposure (CVE) entry describing a software
    /// vulnerability that can be exploited to engage in malicious activity.
    CVE,

    /// Unknown indicator type
    Unknown

}

impl Default for IndicatorType {
        fn default() -> IndicatorType { IndicatorType::Unknown }
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         match *self {
             IndicatorType::Domain => write!(f, "domain"),
             IndicatorType::Hostname => write!(f, "hostname"),
             IndicatorType::Email => write!(f, "email"),
             IndicatorType::MD5 => write!(f, "FileHash-MD5"),
             IndicatorType::SHA1 => write!(f, "FileHash-SHA1"),
             IndicatorType::SHA256 => write!(f, "FileHash-SHA256"),
             IndicatorType::PEHASH => write!(f, "FileHash-PEHASH"),
             IndicatorType::IMPHASH => write!(f, "FileHash-IMPHASH"),
             IndicatorType::Unknown => write!(f, ""),
             _ => write!(f, "{:?}", self)
         }
    }
}

impl FromStr for IndicatorType {
    type Err = ();
    fn from_str(s: &str) -> Result<IndicatorType, Self::Err>{
        match s {
            "IPv4" => Ok(IndicatorType::IPv4),
            "IPv6" => Ok(IndicatorType::IPv6),
            "domain" => Ok(IndicatorType::Domain),
            "hostname" => Ok(IndicatorType::Hostname),
            "email" => Ok(IndicatorType::Email),
            "URL" => Ok(IndicatorType::URL),
            "URI" => Ok(IndicatorType::URI),
            "FileHash-MD5" => Ok(IndicatorType::MD5),
            "FileHash-SHA1" => Ok(IndicatorType::SHA1),
            "FileHash-SHA256" => Ok(IndicatorType::SHA256),
            "FileHash-PEHASH" => Ok(IndicatorType::PEHASH),
            "FileHash-IMPHASH" => Ok(IndicatorType::IMPHASH),
            "CIDR" => Ok(IndicatorType::CIDR),
            "FilePath" => Ok(IndicatorType::FilePath),
            "Mutex" => Ok(IndicatorType::Mutex),
            "CVE" => Ok(IndicatorType::CVE),
            "" => Ok(IndicatorType::Unknown),
            _ => Err(())
        }
    }
}

impl serde::Serialize for IndicatorType {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer {
            let strval = self.to_string();
            let slice: &str = &strval[..];
            serializer.visit_str(slice)
    }
}

impl serde::Deserialize for IndicatorType {
    fn deserialize<D>(deserializer: &mut D) -> Result<IndicatorType, D::Error>
        where D: serde::Deserializer, {

        struct IndicatorVisitor;
        impl serde::de::Visitor for IndicatorVisitor {
            type Value = IndicatorType;
            fn visit_str<E>(&mut self, value: &str) -> Result<IndicatorType, E>
                where E: serde::de::Error {
                match value.parse::<IndicatorType>() {
                    Ok(val) => Ok(val),
                    Err(_) => Err(E::syntax("expected valid IndicatorType"))
                }
            }
        }
        deserializer.visit(IndicatorVisitor)
    }
}

/// Represents an indicator of compromise.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Indicator {

    /// A unique identifier for this indicator
    #[serde(rename="_id")]
    pub id: String,

    /// A timestamp string of when this indicator was created
    pub created: String,

    /// The indicator value
    pub indicator: String,

    /// The indicator type
    #[serde(rename="type")]
    pub indicator_type: IndicatorType,

    /// A description of the indicator
    #[serde(default)]
    pub description: String,
}

/// A threat (or 'pulse' as per the AlienVault OTX) is a collection
/// of indicators that summarize a potential type of attack. It
/// also encapsulates other metadata that describes who submitted
/// the sample, and references to external material relating to
/// the threat..
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Threat {

    /// A unique identifier for the threat
    pub id: String,

    /// Details of who submitted the threat
    pub author_name: String,

    /// A name describing the threat
    pub name: String,

    /// A detailed description of the threat
    #[serde(default)]
    pub description: String,

    /// Date in ISO format when the threat was submitted.
    pub created: String,

    /// Date in ISO format when the threat was last updated.
    pub modified: String,

    /// A collection of indicators that can be used to detect
    /// this threat.
    pub indicators: Vec<Indicator>,

    /// The version of this record
    pub revision: f64,

    /// A list of URLs where further information can be found
    /// about this threat.
    #[serde(default)]
    pub references: Vec<String>,

    /// Any tags that are related to this threat.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A collection of threats returned by an API call. This
/// is paginated to 'limit' number of results.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Threats {

    /// The number of results returned by this request
    #[serde(default)]
    pub count: u64,

    /// Used for pagination
    #[serde(default)]
    pub next: Option<String>,

    /// Used to pagination
    #[serde(default)]
    pub previous: Option<String>,

    /// The list of results returned by the request.
    #[serde(default)]
    pub results: Vec<Threat>,
}

/// A client to access the OTX API. It can be configured using the builder
/// pattern. For example:
///
/// ```
/// extern crate otx;
/// extern crate time;
///
/// use std::ops::Sub;
/// use std::env;
///
/// let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
/// let mut otx = otx::Client::new();
/// otx.url("https://otx.alienvault.com")
///       .apikey(key)
///       .limit(25)
///       .since(time::now().sub(time::Duration::weeks(1)))
///       .each(|threat: &otx::Threat|{
///             println!("{}: {}", threat.id, threat.name);
///             true // Continue iterating
///       });
///
/// ```
pub struct Client {

    apikey: Option<String>,
    client: hyper::Client,
    limit: Option<usize>,
    since: Option<time::Tm>,
    exchange: Option<String>,

}

/// Default settings for client are:
///
///   - **limit**: 25
///   - **since**: Jan 1, 1970 (Resulting in all records).
///   - **exchange**: https://otx.alienvault.com
///   - **apikey**:  None (This MUST be set prior to using the client)
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

    /// Creates a new client using the default settings
    pub fn new() -> Client {
        Default::default()
    }

    /// Specify the how many records to limit each response to.
    /// The default limit is 25.
    pub fn limit<'a>(&'a mut self, val: usize) -> &'a mut Client {
        self.limit = Some(val);
        self
    }

    /// Only return indicators since the specified time.
    /// By default this will be set to the start of the epoch
    /// resulting in all results being returned.
    ///
    /// ```
    /// extern crate otx;
    /// extern crate time;
    ///
    /// use std::ops::Sub;
    ///
    /// let mut otx = otx::Client::new();
    /// let client = otx.apikey("INSERT API KEY HERE")
    ///                 .since(time::now().sub(time::Duration::weeks(1)));
    /// // make a request with client here..
    /// ```
    pub fn since<'a>(&'a mut self, t: time::Tm) -> &'a mut Client {
        self.since = Some(t);
        self
    }

    /// Change the exchange URL. The default is https://otx.alienvault.com.
    pub fn url<'a>(&'a mut self, location: &'a str) -> &'a mut Client {
        self.exchange = Some(String::from(location));
        self
    }

    /// Specify the API key to authenticate the request. This must
    /// be set by the caller prior to making a request.
    pub fn apikey<'a>(&'a mut self, key: &'a str) -> &'a mut Client {
        self.apikey = Some(String::from(key));
        self
    }

    /// Return all threats using the current OTX client configuration.
    /// If Some(page) is supplied this will be the URL used when
    /// making the request (for use with pagination).
    ///
    /// Getting the first page of search results:
    ///
    /// ```
    /// extern crate otx;
    /// use std::env;
    ///
    /// let key = &(env::var("OTX_API_KEY").expect("Please set OTX_API_KEY envvar"))[..];
    /// let mut otx = otx::Client::new();
    /// match otx.apikey(key).threats(None) {
    ///     Some(threats) => {
    ///         for threat in threats.results {
    ///             println!("{} - {}", threat.id, threat.name);
    ///         }
    ///     },
    ///     None => println!("Didn't work..")
    /// }
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

    /// Retrieve a single threat by the supplied ID.
    ///
    /// ```
    /// extern crate otx;
    /// let mut otx = otx::Client::new();
    /// let result = otx.apikey("API_KEY").threat("565da40d4637f2388ab046e9");
    /// match result {
    ///     Some(threat) => println!("{}", threat.id),
    ///     None => println!("Nothing found matching that ID")
    /// }
    /// ```
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

    /// Iterate over all the threats that will be returned by the current
    /// client configuration. If the supplied function returns a false value
    /// the iteration will stop. **NOTE** - this will iterator over _ALL_ results
    /// automatically making paginated requests as needed.
    pub fn each<F>(&self, mut f: F)
        where F: FnMut(&Threat) -> bool {

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
