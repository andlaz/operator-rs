use crate::pod_utils;
use k8s_openapi::api::core::v1::{Node, Pod};
use rand::prelude::SliceRandom;
use std::collections::BTreeMap;

/// This type is used in places where we need label keys with optional values.
pub type LabelOptionalValueMap = BTreeMap<String, Option<String>>;

/// This method can be used to find Pods that do not match a set of Nodes and required labels.
/// For matching pods, we randomly select the amount of pods provided by the replicas (usize)
/// field in `node_and_required_labels`.
///
/// This makes sure that valid pods that exceed the number of desired replicas will be deleted.
///
/// All Pods must match at least one of the node list & required labels combinations.
/// All that don't match and/or exceed the number of replicas will be returned.
///
/// The idea is that you pass in a list of tuples, one tuple for each role group.
/// Each tuple consists of a list of eligible nodes for that role group's LabelSelector, a
/// Map of label keys to optional values and the number of desired replicas.
///
/// To clearly identify Pods (e.g. to distinguish two pods on the same node from each other) they
/// usually need some labels (e.g. a `role` label).
pub fn find_excess_pods<'a>(
    nodes_and_required_labels: &[(Vec<Node>, LabelOptionalValueMap, Option<u16>)],
    existing_pods: &'a [Pod],
) -> Vec<&'a Pod> {
    let expected_pods = find_expected_pods(nodes_and_required_labels, existing_pods);

    // Here we'll filter all existing Pods and will remove all Pods that are in use
    existing_pods.iter()
        .filter(|pod| {
            !expected_pods
                .iter()
                .any(|used_pod|
                    matches!((pod.metadata.uid.as_ref(), used_pod.metadata.uid.as_ref()), (Some(existing_uid), Some(used_uid)) if existing_uid == used_uid))
        })
        .collect()
}

/// Finds all pods matching the required labels.
/// NOTE: This list can contain duplicates!
fn find_expected_pods<'a>(
    nodes_and_required_labels: &[(Vec<Node>, LabelOptionalValueMap, Option<u16>)],
    existing_pods: &'a [Pod],
) -> Vec<&'a Pod> {
    let mut used_pods = Vec::new();

    // For each pair of nodes and labels we try to find valid pods equal to `replicas`.
    // Should there be more than `replicas` pods we'll select a random subset...
    // We collect all of those in one big list.
    // TODO: Because of the randomness it may happen that pods are not
    //   equally shared between the available nodes.
    for (eligible_nodes, mandatory_label_values, replicas) in nodes_and_required_labels {
        let mut found_pods =
            find_valid_pods_for_nodes(eligible_nodes, existing_pods, mandatory_label_values);

        // randomly pick pods according to the amount of replicas that are desired
        match replicas {
            None => used_pods.append(&mut found_pods),
            Some(replicas) => {
                used_pods.append(
                    &mut found_pods
                        .choose_multiple(&mut rand::thread_rng(), usize::from(*replicas))
                        .cloned()
                        .collect(),
                );
            }
        }
    }
    used_pods
}

/// This function can be used to get a list of valid Pods that are assigned
/// (via their `spec.node_name` property) to one of a list of candidate nodes.
///
/// This is useful to find all _valid_ pods (i.e. ones that are actually required by an Operator)
/// so it can be compared against _all_ Pods that belong to the Controller.
///
/// All Pods that are not actually in use can be deleted.
pub fn find_valid_pods_for_nodes<'a>(
    candidate_nodes: &[Node],
    existing_pods: &'a [Pod],
    required_labels: &LabelOptionalValueMap,
) -> Vec<&'a Pod> {
    existing_pods
        .iter()
        .filter(|pod|
            // This checks whether the Pod has all the required labels and if it does
            // it'll try to find a Node with the same `node_name` as the Pod.
            pod_utils::pod_matches_labels(pod, required_labels) && candidate_nodes.iter().any(|node| pod_utils::is_pod_assigned_to_node(pod, node))
        )
        .collect()
}

/// This function can be used to find Nodes that are missing Pods.
///
/// It uses a simple label selector to find matching nodes.
/// This is not a full LabelSelector because the expectation is that the calling code used a
/// full LabelSelector to query the Kubernetes API for a set of candidate Nodes.
///
/// We now need to check whether these candidate nodes already contain a Pod or not.
/// That's why we also pass in _all_ Pods that we know about and one or more labels (including optional values).
/// This method checks if there are pods assigned to a node and if these pods have all required labels.
/// These labels are _not_ meant to be user-defined but can be used to distinguish between different Pod types.
///
/// You would usually call this function once per role group.
///
/// # Example
///
/// * HDFS has multiple roles (NameNode, DataNode, JournalNode)
/// * Multiple roles may run on the same node
///
/// To check whether a certain Node is already running a NameNode Pod it is not enough to just check
/// if there is a Pod assigned to that node.
/// We also need to be able to distinguish the different roles.
/// That's where the labels come in.
/// In this scenario you'd add a label `app.kubernetes.io/component` with the value `NameNode` to each
/// NameNode Pod.
/// And this is the label you can now filter on using the `label_values` argument.
///
/// Additionally the replicas field of a role group is taken into account. When selecting nodes,
/// a random subset representing the size difference between "replicas" and "nodes_that_need_pods"
/// is selected. If replicas is None, all "nodes_that_need_pods" are returned.
///
/// NOTE: This method currently does not support multiple instances per Node!
/// Multiple instances on one node need to be described in different role groups (and with different
/// settings like ports etc.)
pub fn find_nodes_that_need_pods<'a>(
    candidate_nodes: &'a [Node],
    existing_pods: &[Pod],
    label_values: &BTreeMap<String, Option<String>>,
    replicas: Option<u16>,
) -> Vec<&'a Node> {
    let nodes_that_need_pods = candidate_nodes
        .iter()
        .filter(|node| {
            !existing_pods.iter().any(|pod| {
                pod_utils::is_pod_assigned_to_node(pod, node)
                    && pod_utils::pod_matches_labels(pod, label_values)
            })
        })
        .collect::<Vec<&Node>>();

    let valid_pods_for_nodes =
        find_valid_pods_for_nodes(candidate_nodes, existing_pods, label_values);

    if let Some(replicas) = replicas {
        let diff = usize::from(replicas) - valid_pods_for_nodes.len();
        // we found every matching node here, now it is time to filter if we found too many nodes
        return if diff > 0 {
            nodes_that_need_pods
                .choose_multiple(&mut rand::thread_rng(), diff)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
    }

    nodes_that_need_pods
}
