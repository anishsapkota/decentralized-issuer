use crate::node::process_message;
use crate::node_state::NodeState;
use futures_util::stream::StreamExt;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{ClientConfig, TopicPartitionList};
use std::error::Error;

pub async fn create_consumer(
    node_id: u32,
    partition: i32,
) -> Result<StreamConsumer, Box<dyn Error>> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", format!("node-{}", node_id))
        .set("bootstrap.servers", "localhost:9092")
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "latest")
        .create()?;

    // let mut tpl = TopicPartitionList::new();
    // tpl.add_partition("commitments", partition);
    // tpl.add_partition("key-gen-finished-announcements", partition);
    // tpl.add_partition(&format!("shares-{}", node_id), partition);
    // tpl.add_partition("signing_commitments", partition);
    // tpl.add_partition("signing_responses", partition);
    // tpl.add_partition("heartbeats", partition);
    // tpl.add_partition("master_announcements", partition);
    // tpl.add_partition("signing_requests", partition);
    // tpl.add_partition("signing_results", partition);

    consumer
        .subscribe(&[
            "commitments",
            &format!("shares-{}", node_id),
            "signing_commitments",
            "signing_responses",
            "key-gen-finished-announcements",
            "signing_results",
            "heartbeats",
            "master_announcements",
            "signing_requests",
        ])
        .expect("Can't subscribe to specified topics");

    //consumer.assign(&tpl).expect("Error assigning partitions");
    Ok(consumer)
}

pub async fn consume_messages(state: NodeState, consumer: StreamConsumer) {
    let mut message_stream = consumer.stream();

    while let Some(result) = message_stream.next().await {
        match result {
            Ok(borrowed_message) => {
                let state_clone = state.clone();
                let owned_message = borrowed_message.detach();
                tokio::spawn(async move {
                    process_message(&state_clone, owned_message).await;
                });
            }
            Err(e) => {
                println!("Error while reading from stream. Error: {:?}", e);
            }
        }
    }
}
