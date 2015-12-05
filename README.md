## otx - Open threat exchange client

Rust bindings for the [AlienVault](
://www.alienvault.com/open-threat-exchange) OTX v1 API.

### Status

Provides read-only access to pulse information published on
otx.alienvault.com. You will need to sign-up to AlienVault
and get an API key in order to use this library.

##### TODO
  - Get code to run on stable instead of just nightly.
  - Write some documentation.
  - Figure out how to replace .each(|x|) with a nicer more
    idiomatic Rust iterator.
  - Add travis-ci.org integration.
  - Pin to specific library versions
  - Cut an official release and get it published as a crate.


### Example

```rust

// Full source in examples/demo.rs
// $ cargo run --example demo

    // Create a new client, and iterate over each threat that
    // occurred within the last week. Pulse information will
    // be limited to 25 results per page (or request).
    let mut otx = otx::Client::new();
    otx.url("https://otx.alienvault.com")
       .apikey("INSERT YOUR API KEY").limit(25)
       .since(time::now().sub(time::Duration::weeks(1)))
       .each(|threat|{
           println!("{}: {}", threat.id, threat.name);
           true // Continue iterating
       });

```
