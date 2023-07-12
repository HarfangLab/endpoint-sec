use endpoint_sec::Client;

#[test]
fn test_client_can_connect() {
    Client::new(|_client, _msg| {
        println!("Got a message!");
    })
    .unwrap();
}
