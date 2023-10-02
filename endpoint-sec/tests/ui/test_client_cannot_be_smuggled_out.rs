fn main() {
    use std::cell::RefCell;

    use endpoint_sec::Client;

    Client::new(|client, _| {
        let other_client = Client::new(|_, _| {}).unwrap();
        // Tear the `client` out of the `&mut` reference.
        let smuggled_client = std::mem::replace(client, other_client);
        thread_local! {
            static CLIENT_SMUGGLING: RefCell<Option<Client<'static>>> = RefCell::new(None);
        }
        CLIENT_SMUGGLING.with(|r| *r.borrow_mut() = Some(smuggled_client));
    });
}
