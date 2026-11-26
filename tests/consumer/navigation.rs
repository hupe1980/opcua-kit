// Exercise a downstream default-feature Rust consumer against both independent SDKs.
use opcua_kit::{
    Client, NodeId, Sample,
    client::{BrowseError, BrowseName, SubscriptionError},
};
use std::time::Duration;

const NS: &str = "urn:fixture:hvac";
const TYPES: &str = "urn:fixture:types";

fn node(id: &str) -> NodeId {
    NodeId::new(NS, format!("s={id}")).unwrap()
}

pub async fn exercise(client: &Client, python: bool) {
    let root = node("Navigation");
    let area = node("Area");
    let counter = node("Counter");
    let area_name = BrowseName::new(NS, "Area").unwrap();
    let counter_name = BrowseName::new(NS, "Counter").unwrap();
    assert_eq!(
        client
            .resolve_path(&root, &[area_name, counter_name.clone()])
            .await
            .unwrap(),
        counter,
    );
    let entries = client.browse_children(&area).await.unwrap();
    let meters: Vec<_> = entries
        .iter()
        .filter(|r| r.browse_name.name == "Counter")
        .collect();
    assert_eq!(meters.len(), 2);
    assert!(
        meters
            .iter()
            .any(|e| e.browse_name == counter_name && e.node == counter)
    );
    let other = BrowseName::new(TYPES, "Counter").unwrap();
    assert_eq!(
        client.resolve_path(&area, &[other]).await.unwrap(),
        node("OtherCounter")
    );
    assert!(matches!(
        client
            .resolve_path(&area, &[BrowseName::new(NS, "missing").unwrap()])
            .await,
        Err(BrowseError::NotFound(0))
    ));
    if python {
        assert!(matches!(
            client.browse_children(&node("RemoteUnit")).await,
            Err(BrowseError::InvalidReference)
        ));
        assert!(matches!(
            client
                .resolve_path(&area, &[BrowseName::new(NS, "Twin").unwrap()])
                .await,
            Err(BrowseError::Ambiguous(0))
        ));
    }

    let interval = Duration::from_millis(25);
    let wait = Duration::from_secs(5);
    let monitored = [node("Steady"), counter.clone(), node("Steady")];
    let mut group = client.subscribe_many(&monitored, interval).await.unwrap();
    for (revision, requested) in group.items().iter().zip(&monitored) {
        assert_eq!(&revision.node, requested);
        assert!(revision.sampling_interval > Duration::ZERO);
        assert!((2..=32).contains(&revision.queue_size));
    }
    assert_eq!(group.items().len(), monitored.len());
    let mut seen = [false; 3];
    tokio::time::timeout(wait, async {
        while !seen.iter().all(|&received| received) {
            let change = group.next(wait).await.unwrap();
            let sample = Sample::<u64>::from_raw(&change.value).unwrap();
            match change.index {
                0 | 2 => assert_eq!(sample.value, Some(42)),
                1 => assert!(sample.value.unwrap() > (1 << 53)),
                index => panic!("unrequested item index {index}"),
            }
            seen[change.index] = true;
        }
    })
    .await
    .unwrap();
    drop(group);

    // Initial notifications for the maximum sized group all fit the shared queue.
    let repeated = vec![node("Steady"); 32];
    let mut full = client.subscribe_many(&repeated, interval).await.unwrap();
    let mut received = std::collections::BTreeSet::new();
    for _ in 0..repeated.len() {
        received.insert(full.next(wait).await.unwrap().index);
    }
    assert!(received.into_iter().eq(0..repeated.len()));
    drop(full);
    for invalid in [Vec::new(), vec![node("Steady"); 33]] {
        assert!(matches!(
            client.subscribe_many(&invalid, interval).await,
            Err(SubscriptionError::ItemCount)
        ));
    }
    assert!(matches!(
        client
            .subscribe_many(
                &[node("Steady"), NodeId::new("urn:missing", "i=1").unwrap()],
                interval
            )
            .await,
        Err(SubscriptionError::Session(
            opcua_kit::ReadError::UnknownNamespace { index: 1 }
        ))
    ));
    assert!(matches!(
        client
            .subscribe_many(&[node("Steady"), node("NoSuchItem")], interval)
            .await,
        Err(SubscriptionError::ItemRejected { index: 1, .. })
    ));
    if python {
        let mut idle = client
            .subscribe_many(&[node("Steady"), node("Idle")], interval)
            .await
            .unwrap();
        let first = idle.next(wait).await.unwrap();
        let second = idle.next(wait).await.unwrap();
        assert_ne!(first.index, second.index);
        assert!(matches!(
            idle.next(Duration::from_millis(40)).await,
            Err(SubscriptionError::Timeout)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), idle.next(wait))
                .await
                .is_err()
        );
        // This read tells the independent test server to change Idle for the first time.
        assert_eq!(
            client
                .read_scalar::<u64>(&node("Resume"))
                .await
                .unwrap()
                .value,
            Some(1)
        );
        let resumed = idle.next(wait).await.unwrap();
        assert_eq!(resumed.index, 1);
        assert_eq!(
            Sample::<u64>::from_raw(&resumed.value).unwrap().value,
            Some(8)
        );
        drop(idle);
        let mut lossy = client
            .subscribe_many(&[node("Steady"), node("Overflow")], interval)
            .await
            .unwrap();
        loop {
            match lossy.next(wait).await {
                Ok(change) => assert_eq!(change.index, 0),
                Err(SubscriptionError::ItemOverflow {
                    index: 1,
                    status: 0x480,
                }) => break,
                other => panic!("unexpected group result: {other:?}"),
            }
        }
        assert!(matches!(
            lossy.next(wait).await,
            Err(SubscriptionError::Ended)
        ));
    }
    let mut steady = client.subscribe(&node("Steady"), interval).await.unwrap();
    assert!((2..=32).contains(&steady.server_queue_size()));
    let raw = steady.next(wait).await.unwrap();
    assert_eq!(Sample::<u64>::from_raw(&raw).unwrap().value, Some(42));
    assert!(matches!(
        steady.next(Duration::from_millis(50)).await,
        Err(SubscriptionError::Timeout)
    ));
    drop(steady);

    let mut changes = client.subscribe(&counter, interval).await.unwrap();
    let first = Sample::<u64>::from_raw(&changes.next(wait).await.unwrap())
        .unwrap()
        .value
        .unwrap();
    let second = Sample::<u64>::from_raw(&changes.next(wait).await.unwrap())
        .unwrap()
        .value
        .unwrap();
    assert!(second > first && first > (1 << 53));
    if python {
        let mut overflow = client.subscribe(&node("Overflow"), interval).await.unwrap();
        assert!(matches!(
            overflow.next(wait).await,
            Err(SubscriptionError::ServerOverflow(0x480))
        ));
        assert!(matches!(
            overflow.next(wait).await,
            Err(SubscriptionError::Ended)
        ));
        drop(overflow);
        drop(changes);
        let mut slots = Vec::new();
        for _ in 0..8 {
            slots.push(client.subscribe(&node("Steady"), interval).await.unwrap());
        }
        assert!(matches!(
            client.subscribe(&node("Steady"), interval).await,
            Err(SubscriptionError::Limit)
        ));
        drop(slots.pop());
        slots.push(client.subscribe(&node("Steady"), interval).await.unwrap());
    } else {
        // Let more than 32 changes arrive without polling. The consumer must learn
        // about local loss before any further queued data are reported as usable.
        let mut lost = false;
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match changes.next(wait).await {
                Err(SubscriptionError::LocalOverflow) => {
                    lost = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("unexpected subscription result: {error}"),
            }
        }
        assert!(lost, "expected local notification overflow");
        assert!(matches!(
            changes.next(wait).await,
            Err(SubscriptionError::Ended)
        ));
        drop(changes);
        let wide = client
            .browse_children(&node("Wide"))
            .await
            .map(|entries| entries.len());
        assert!(
            matches!(
                wide,
                Err(BrowseError::Limit | BrowseError::InvalidReference)
            ),
            "{wide:?}"
        );
    }
}
