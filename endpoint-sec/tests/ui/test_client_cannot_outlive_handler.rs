use endpoint_sec::Client;

fn main() {
    let mut client = {
        let v = vec![1, 2, 3];
        let handler = |_: &mut Client<'_>, _| {
            dbg!(&v);
        };
        let client = Client::new(handler).unwrap();

        std::mem::drop(handler);
        client
    };
    client.unsubscribe_all();
}
