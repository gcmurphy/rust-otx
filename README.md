## otx - Open threat exchange client

Rust bindings for the OTXv1 API available by AlienVault.

### Status

Provides read-only access to pulse information published on
otx.alienvault.com. You will need to sign-up to AlienVault
and get an API key in order to use this library.

##### TODO
  - Get code to run on stable instead of just nightly.
  - Write some documentation.
  - Write some proper unittests.
  - Move existing tests into tests directory, as they are more
    integration tests.
  - Figure out how to replace .each(|x|) with a nicer more
    idiomatic Rust iterator.
  - Add travis-ci.org integration.
  - Cut an official release and get it published as a crate.


### Example

```rust

// Full source in examples/demo.rs
// $ cargo run --example demo

    // Create a new client, and iterate over each threat that
    // occurred within the last week.
    let mut otx = otx::Client::new();
    otx.apikey(key).limit(25)
       .since(time::now().sub(time::Duration::weeks(1)))
       .each(|threat|{
           println!("{}: {}", threat.id, threat.name);
           true // Continue iterating
       });

```
