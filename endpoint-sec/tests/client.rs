use endpoint_sec::Client;

#[test]
fn test_client_can_connect() {
    Client::new(|_client, _msg| {
        println!("Got a message!");
    })
    .unwrap();
}

#[test]
fn reproduce_double_drop() {
    #[derive(Debug)]
    struct DropCnt {
        // To avoid segfaulting in case we regress, we leak the allocation here.
        cnt: std::mem::ManuallyDrop<Box<u32>>,
    }
    impl Drop for DropCnt {
        fn drop(&mut self) {
            println!("Dropping, counter at {}", **self.cnt);
            **self.cnt += 1;
            if **self.cnt > 1 {
                panic!("Dropped more than once");
            }
        }
    }
    let drop_cnt = DropCnt {
        cnt: std::mem::ManuallyDrop::new(Box::new(0)),
    };
    Client::new(move |_client, _msg| {
        println!("{drop_cnt:?}");
    })
    .unwrap();
}
