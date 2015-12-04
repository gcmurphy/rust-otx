extern crate time;
extern crate otx;

use std::env;
use std::ops::Sub;

fn main(){

    // Load API key from enviroment
    let key = &(env::var("OTX_API_KEY").expect("Please set environment variable OTX_API_KEY"))[..];

    // Create a new client, and iterate over each threat that
    // occurred within the last week.
    let mut otx = otx::Client::new();
    otx.apikey(key).limit(25)
       .since(time::now().sub(time::Duration::weeks(1)))
       .each(|threat|{
           println!("{}: {}", threat.id, threat.name);
           true // Continue iterating
       });
}
