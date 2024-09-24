use communityid::Flow;
use serde::Deserialize;
use std::{fs, net::IpAddr, str::FromStr};

#[derive(Deserialize)]
struct BaselineStruct {
    proto: u8,
    saddr: String,
    daddr: String,
    sport: Option<u16>,
    dport: Option<u16>,
    communityid: String,
}

impl From<&BaselineStruct> for Flow {
    fn from(value: &BaselineStruct) -> Self {
        if value.sport.is_some() {
            Self::new(
                value.proto.into(),
                IpAddr::from_str(&value.saddr).unwrap(),
                value.sport.unwrap(),
                IpAddr::from_str(&value.daddr).unwrap(),
                value.dport.unwrap(),
            )
        } else {
            Self::partial(
                value.proto.into(),
                IpAddr::from_str(&value.saddr).unwrap(),
                IpAddr::from_str(&value.daddr).unwrap(),
            )
        }
    }
}

// testing out the baseline file provided by the community-id-spec
// https://github.com/corelight/community-id-spec/blob/master/baseline/baseline_deflt.json
#[test]
fn test_baseline_default() {
    let data: Vec<BaselineStruct> =
        serde_json::from_str(&fs::read_to_string("./tests/data/baseline_default.json").unwrap())
            .unwrap();

    for b in data.iter() {
        let f = Flow::from(b);
        assert_eq!(f.community_id_v1(0).base64(), b.communityid)
    }
}

// testing baseline file provided by community-id-spec
// https://github.com/corelight/community-id-spec/blob/master/baseline/baseline_seed1.json
#[test]
fn test_baseline_seed1() {
    let data: Vec<BaselineStruct> =
        serde_json::from_str(&fs::read_to_string("./tests/data/baseline_seed1.json").unwrap())
            .unwrap();

    for b in data.iter() {
        let f = Flow::from(b);
        assert_eq!(f.community_id_v1(1).base64(), b.communityid)
    }
}

// testing baseline file provided by community-id-spec
// https://github.com/corelight/community-id-spec/blob/master/baseline/baseline_nob64.json

#[test]
fn test_baseline_no_base64() {
    let data: Vec<BaselineStruct> =
        serde_json::from_str(&fs::read_to_string("./tests/data/baseline_nob64.json").unwrap())
            .unwrap();

    for b in data.iter() {
        let f = Flow::from(b);
        assert_eq!(f.community_id_v1(0).hexdigest(), b.communityid)
    }
}
