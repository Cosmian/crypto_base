// This construct is a simple and efficient range-constrained PRF from the
// tree-based GGM PRF [GGM84]. This instantiation has been described by
// Kiayiaset al. [KPTZ13](https://people.csail.mit.edu/stavrosp/papers/ccs2013/CCS13_DPRF.pdf) and is called best range cover (BRC)
// This is the hardware independent version

use std::{cmp, convert::TryFrom};

use crate::CryptoBaseError;
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, NewBlockCipher},
    Aes256,
};

/// Tests whether the AES native interface is available on this machine
///
/// The BRC constrained PRF will NOT run if it is not available
#[must_use]
pub fn aes_ni_available() -> bool {
    #[cfg(all(not(target_arch = "wasm32"), not(windows)))]
    {
        if let Some(information) = cupid::master() {
            return information.aesni();
        }
    }
    false
}

#[inline]
fn g0(k: &[u8; 32]) -> [u8; 32] {
    let cipher = Aes256::new(GenericArray::from_slice(k));
    let mut data = *k;
    data[15] ^= 0b0000_0000;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut data[0..16]));
    data[31] ^= 0b0000_0000;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut data[16..32]));
    data
}

#[inline]
fn g1(k: &[u8; 32]) -> [u8; 32] {
    let cipher = Aes256::new(GenericArray::from_slice(k));
    let mut data = *k;
    data[15] ^= 0b0000_0001;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut data[0..16]));
    data[31] ^= 0b0000_0001;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut data[16..32]));
    data
}

#[derive(Clone)]
pub struct Node {
    level: u8,
    k: [u8; 32],
}
#[derive(Clone, Default)]
pub struct Trapdoor {
    pub nodes: Vec<Node>,
}

impl Trapdoor {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.clone().into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError> {
        Self::try_from(bytes).map_err(CryptoBaseError::ConversionError)
    }
}

/// Serialization of a Trapdoor into bytes
impl From<Trapdoor> for Vec<u8> {
    fn from(t: Trapdoor) -> Self {
        let mut b: Self = Self::with_capacity(4 + (1 + 32) * t.nodes.len());
        b.extend_from_slice(&(t.nodes.len() as u32).to_be_bytes());
        for n in t.nodes {
            b.push(n.level);
            b.extend_from_slice(&n.k);
        }
        b
    }
}

/// De-serialization of Trapdoor from bytes
impl TryFrom<Vec<u8>> for Trapdoor {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

/// De-serialization of Trapdoor from bytes
impl TryFrom<&[u8]> for Trapdoor {
    type Error = String;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        if b.len() < 4 {
            return Err("Invalid serialized trapdoor".to_string());
        }
        let mut l_a: [u8; 4] = [0, 0, 0, 0];
        l_a.copy_from_slice(&b[0..4]);
        let l = u32::from_be_bytes(l_a) as usize;
        let mut nodes: Vec<Node> = Vec::with_capacity(l);
        for i in 0..l {
            let pos = i * 33;
            let mut k: [u8; 32] = Default::default();
            k.copy_from_slice(&b[4 + pos + 1..4 + pos + 33]);
            nodes.push(Node {
                level: b[4 + pos],
                k,
            })
        }
        Ok(Self { nodes })
    }
}

/// Generate a Trapdoor for the given range [`min_c`, `max_c`] index.
///
/// The trapdoor will allow the generation of all pseudo-random values
/// seeded by `k` from index `min_c` to `max_c` both included
/// Return the minimal key list needed to compute the output
///
/// e.g. trapdoor(0b0000, 0b0110, key(.), 4) will return the 3 nodes [.]
// root                                                 .
//                                    _________________/ \_________________
//                                   /                                     \
// level 3                          0                                       1
//                          _______/ \_______                       _______/ \_______
//                         /                 \                     /                 \
// level 2               [0]                  1                   0                   1
//                     __/ \__             __/ \__             __/ \__             __/ \__
//                    /       \           /       \           /       \           /       \
// level 1           0         1        [0]        1         0         1         0         1
//                  / \       / \       / \       / \       / \       / \       / \       / \
// level 0         0   1     0   1     0   1    [0]  1     0   1     0   1     0   1     0   1
//                 |   |     |   |     |   |     |   |     |   |     |   |     |   |     |   |
//               0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
//                                               ▲
pub fn trapdoor_range(
    min_c: Option<u32>,
    max_c: Option<u32>,
    limit: Option<u32>,
    k: &[u8; 32],
    level: u8,
) -> Trapdoor {
    // Need at least two values set in (min_c, max_c, limit)
    let (c_min, c_max) = match (min_c, max_c, limit) {
        (None, None, None) => (0, (1 << level) - 1),
        (None, None, Some(l)) => (0, cmp::min(l - 1, (1 << level) - 1)),
        (None, Some(ma), None) => (0, ma),
        (Some(mi), None, None) => (mi, (1 << level) - 1),
        (Some(mi), Some(ma), None) => (mi, ma),
        (Some(mi), None, Some(l)) => (mi, mi.saturating_add(l - 1)),
        (None, Some(ma), Some(l)) => (ma.saturating_sub(l - 1), ma),
        (Some(mi), Some(ma), Some(l)) => (mi, cmp::min(ma, mi.saturating_add(l - 1))),
    };
    Trapdoor {
        nodes: trapdoor_inner_range_no_rec(c_min, c_max, k, level),
    }
}

fn trapdoor_inner_range_no_rec(min_c: u32, max_c: u32, k: &[u8; 32], level: u8) -> Vec<Node> {
    let mut trapdoor = Vec::<Node>::new();
    if max_c < min_c {
        return trapdoor;
    }
    // compute the first node where 'min_c' and 'max_c' differs
    let mut shift = level - 1;
    let mut node = *k;
    loop {
        let bit_min = (min_c >> shift) & 0x01;
        let bit_max = (max_c >> shift) & 0x01;
        if bit_min != bit_max {
            break;
        }
        // bit_min = bit_max
        node = if bit_min == 0 { g0(&node) } else { g1(&node) };
        if shift == 0 {
            // case min_c = max_c
            return vec![Node { level: 0, k: node }];
        } else {
            shift -= 1
        };
    }
    //println!("level {} shift {} min {}, max {}", level, shift, min_c, max_c);
    // compute min_c and max_c from the deepest root
    let mask = (1 << (shift + 1)) - 1;
    let min_c = min_c & mask;
    let max_c = max_c & mask;
    let root = shift;
    let root_node = node;
    //println!("min {} max {} root {} mask {}", min_c, max_c, root, mask);
    // traverse the left subtree
    // check if we have the leftmost leaf
    if min_c == 0 {
        // check if we have the rightmost leaf (thus the whole tree [from the deepest
        // root])
        if max_c == mask {
            return vec![Node {
                level: shift + 1,
                k: node,
            }];
        } else {
            // else we have the whole left subtree
            trapdoor.push(Node {
                level: shift,
                k: g0(&node),
            })
        }
    } else {
        // index of the first one in min_c (ie deepest leftmost subtree)
        let mu = (min_c.trailing_zeros() + 1) as u8;
        let mut shift = root - 1;
        let mut node = g0(&root_node);
        //println!("min {} max {} root {} mu {}", min_c, max_c, shift, mu);
        while shift >= mu {
            let bit = (min_c >> shift) & 0x01;
            if bit == 0 {
                //println!("shift {}", shift);
                trapdoor.push(Node {
                    level: shift,
                    k: g1(&node),
                });
                node = g0(&node);
            } else {
                node = g1(&node);
            }
            shift -= 1;
        }
        // finally add the deepest leftmost subtree
        trapdoor.push(Node {
            level: mu - 1,
            k: g1(&node),
        });
    }

    // traverse the right subtree
    if max_c == mask {
        // check if we have the rightmost leaf (thus the whole tree [from the deepest
        // root])
        trapdoor.push(Node {
            level: root,
            k: g1(&root_node),
        });
    } else {
        // index of the first zero in max_c (ie deepest leftmost subtree)
        let nu = (max_c.trailing_ones() + 1) as u8;
        let mut shift = root - 1;
        let mut node = g1(&root_node);
        //println!("min {} max {} root {} nu {}", min_c, max_c, shift, nu);
        while shift >= nu {
            let bit = (max_c >> shift) & 0x01;
            if bit == 1 {
                trapdoor.push(Node {
                    level: shift,
                    k: g0(&node),
                });
                node = g1(&node);
            } else {
                node = g0(&node);
            }
            shift -= 1;
        }
        // finally add the deepest leftmost subtree
        trapdoor.push(Node {
            level: nu - 1,
            k: g0(&node),
        });
    }

    trapdoor
}

#[must_use]
pub fn trapdoor(max_c: u32, k: &[u8; 32], level: u8) -> Trapdoor {
    Trapdoor {
        nodes: trapdoor_inner(max_c, k, level, 0),
    }
}

fn trapdoor_inner(max_c: u32, k: &[u8; 32], level: u8, c: u32) -> Vec<Node> {
    let bit = (max_c >> (level - 1)) & 0x01;
    // println!("   level: {}, bit: {}, max_c: {}", level, bit, max_c);
    if bit == 0 {
        let g0_k = g0(k);
        if level == 1 {
            return vec![Node { level: 0, k: g0_k }];
        }
        return trapdoor_inner(max_c, &g0_k, level - 1, c << 1);
    }
    // bit = 1
    if level == 1 {
        return vec![Node { level, k: *k }];
    }
    // mark the (fork) level at which we got the first 1
    let level_bit_1 = level;
    let k_bit_1 = *k;
    // going down the branch on the 1 "side"
    let mut l = level;
    loop {
        //go down
        l -= 1;
        let bit = (max_c >> (l - 1)) & 0x01;
        if bit == 1 {
            if l == 1 {
                // the leaf was reached, there are only ones on the right,
                // take all subtree values from the fork point
                return vec![Node {
                    level: level_bit_1,
                    k: k_bit_1,
                }];
            }
            // keep going down
            continue;
        }
        // bit == 0 => take the g0 value on the left of the fork
        // and go down the tree on the right
        let mut v = vec![Node {
            k: g0(&k_bit_1),
            level: level_bit_1 - 1,
        }];
        v.extend(trapdoor_inner(
            max_c,
            &g1(&k_bit_1),
            level_bit_1 - 1,
            (c << 1) | 0x01,
        ));
        return v;
    }
}

/// Generate all the pseudo random values specified by the `Trapdoor`
#[must_use]
pub fn leaves(trapdoor: &Trapdoor) -> Vec<[u8; 32]> {
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(1 << trapdoor.nodes[0].level);
    for n in &trapdoor.nodes {
        leaves_inner(&n.k, n.level, &mut leaves);
    }
    leaves
}

fn leaves_inner(k: &[u8; 32], level: u8, leaves: &mut Vec<[u8; 32]>) {
    if level == 0 {
        leaves.push(*k);
        return;
    }
    let l = level - 1;
    // zero
    leaves_inner(&g0(k), l, leaves);
    // one
    leaves_inner(&g1(k), l, leaves);
}

/// Retrieve the leaf value for the given `c` index
/// starting from the node at `level` with `k` value
#[must_use]
pub fn leaf(k: &[u8; 32], level: u8, c: u32) -> [u8; 32] {
    if level == 0 {
        return *k;
    }
    let bit = (c >> (level - 1)) & 0x01;
    let next_k = if bit == 0 { g0(k) } else { g1(k) };
    leaf(&next_k, level - 1, c)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use rand::{prelude::*, RngCore, SeedableRng};
    use rand_hc::Hc128Rng;
    use tracing::debug;

    use super::{g0, g1, Node, Trapdoor};

    struct CsRng {
        rng: Hc128Rng,
    }

    impl CsRng {
        pub fn new() -> Self {
            Self {
                rng: Hc128Rng::from_entropy(),
            }
        }

        pub fn random_256_bits(&mut self) -> [u8; 32] {
            let mut v = [0_u8; 32];
            self.rng.fill_bytes(&mut v);
            v
        }
    }

    impl Default for CsRng {
        fn default() -> Self {
            Self::new()
        }
    }

    #[test]
    fn test_show_info() {
        let information = cupid::master();
        println!("{:#?}", information);
        if let Some(information) = information {
            if information.sse4_2() {
                println!("SSE 4.2 Available");
            }
            if information.aesni() {
                println!("AES NI Available");
            }
        }
    }

    #[test]
    fn test_g0_g1() {
        let mut rng = CsRng::new();
        let r = rng.random_256_bits();
        let init_0101: [u8; 32] = g0(&g1(&g0(&g1(&r))));
        for _i in 0..1000_usize {
            assert_eq!(init_0101, g0(&g1(&g0(&g1(&r)))));
        }
        let mut prev_0101 = init_0101;
        for _i in 0..1000_usize {
            let r_prime = rng.random_256_bits();
            let next_0101: [u8; 32] = g0(&g1(&g0(&g1(&r_prime))));
            assert_ne!(prev_0101, next_0101);
            prev_0101 = next_0101;
        }
        for _i in 0..1000_usize {
            let r_prime = rng.random_256_bits();
            assert_ne!(g0(&r_prime), g1(&r_prime));
            assert_ne!(r_prime, g0(&r_prime));
            assert_ne!(r_prime, g1(&r_prime));
        }
    }

    #[derive(Clone)]
    struct TreeNode {
        _level: u8,
        _c: usize,
        k: [u8; 32],
        _0: Option<Box<TreeNode>>,
        _1: Option<Box<TreeNode>>,
    }

    fn generate_tree(c: usize, k: &[u8; 32], level: u8, leaves: &mut Vec<TreeNode>) -> TreeNode {
        // println!(
        //     "Level {} {}, c: {}, k: {}",
        //     level,
        //     if c & 0x1 == 0x01 { "ONE " } else { "ZERO" },
        //     c,
        //     hex::encode(&k)
        // );
        if level == 0 {
            let n = TreeNode {
                _level: level,
                _c: c,
                k: *k,
                _0: None,
                _1: None,
            };
            leaves.push(n.clone());
            return n;
        }
        TreeNode {
            _level: level,
            _c: c,
            k: *k,
            _0: Some(Box::new(generate_tree(c << 1, &g0(k), level - 1, leaves))),
            _1: Some(Box::new(generate_tree(
                (c << 1) | 0x01,
                &g1(k),
                level - 1,
                leaves,
            ))),
        }
    }

    #[test]
    fn test_leaves() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let level = 16;
        let mut ref_leaves: Vec<TreeNode> = Vec::with_capacity(1 << level);
        let zero_tree = generate_tree(0, &g0(&k), level - 1, &mut ref_leaves);
        let one_tree = generate_tree(1, &g1(&k), level - 1, &mut ref_leaves);
        let _root_node = TreeNode {
            _level: level,
            _c: 0,
            k,
            _0: Some(Box::new(zero_tree)),
            _1: Some(Box::new(one_tree)),
        };

        let leaves = super::leaves(&Trapdoor {
            nodes: vec![Node { level, k }],
        });
        assert_eq!(ref_leaves.len(), 1 << level);
        assert_eq!(leaves.len(), 1 << level);
        for i in 0..(1 << level) as usize {
            assert_eq!(ref_leaves[i].k, leaves[i]);
        }
    }

    #[test]
    fn test_leaf() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let level = 16;
        let leaves = super::leaves(&Trapdoor {
            nodes: vec![Node { level, k }],
        });
        for (c, ref_leaf) in leaves.iter().enumerate() {
            let lf = super::leaf(&k, level, c as u32);
            assert_eq!(*ref_leaf, lf);
        }
    }

    #[test]
    fn test_trapdoor() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let level = 4;
        let root_node = super::Node { level, k };
        let leaves = super::leaves(&Trapdoor {
            nodes: vec![root_node],
        });
        // 0b0000
        let max_c = 0b0000;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0000 len");
        assert_eq!(0, trapdoor.nodes[0].level, "0b0000 level");
        // assert_eq!(leaves[0].k, trapdoor.nodes[0].k);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0000 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0000 leave {}", i);
        }
        // 0b0001
        let max_c = 0b0001_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0001 len");
        assert_eq!(1, trapdoor.nodes[0].level, "0b0001 level");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0001 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0001 leave {}", i);
        }
        // 0b0011
        let max_c = 0b0011_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0011 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0011 level");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0011 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0011 leave {}", i);
        }
        // 0b0101
        let max_c = 0b0101_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 2, "0b0101 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0101 level 1");
        assert_eq!(1, trapdoor.nodes[1].level, "0b0101 level 2");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0101 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0101 leave {}", i);
        }
        // 0b0110
        let max_c = 0b0110_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 3, "0b0110 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0110 level 1");
        assert_eq!(1, trapdoor.nodes[1].level, "0b0110 level 2");
        assert_eq!(0, trapdoor.nodes[2].level, "0b0110 level 3");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0110 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0110 leave {}", i);
        }
        // 0b0111
        let max_c = 0b0111_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1);
        assert_eq!(3, trapdoor.nodes[0].level);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len());
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i]);
        }
        // 0b1111
        let max_c = 0b1111_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1);
        assert_eq!(4, trapdoor.nodes[0].level);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len());
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i]);
        }
        // 0b1110
        let max_c = 0b1110_u32;
        let trapdoor = super::trapdoor(max_c, &k, level);
        assert_eq!(trapdoor.nodes.len(), 4);
        assert_eq!(3, trapdoor.nodes[0].level);
        assert_eq!(2, trapdoor.nodes[1].level);
        assert_eq!(1, trapdoor.nodes[2].level);
        assert_eq!(0, trapdoor.nodes[3].level);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len());
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i]);
        }
    }

    #[test]
    fn test_trapdoor_range_min_0() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let level = 4;
        let root_node = super::Node { level, k };
        let leaves = super::leaves(&Trapdoor {
            nodes: vec![root_node],
        });
        // 0b0000
        let max_c = 0b0000;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0000 len");
        assert_eq!(0, trapdoor.nodes[0].level, "0b0000 level");
        // assert_eq!(leaves[0].k, trapdoor.nodes[0].k);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0000 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0000 leave {}", i);
        }
        // 0b0001
        let max_c = 0b0001_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0001 len");
        assert_eq!(1, trapdoor.nodes[0].level, "0b0001 level");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0001 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0001 leave {}", i);
        }
        // 0b0011
        let max_c = 0b0011_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0011 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0011 level");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0011 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0011 leave {}", i);
        }
        // 0b0101
        let max_c = 0b0101_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 2, "0b0101 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0101 level 1");
        assert_eq!(1, trapdoor.nodes[1].level, "0b0101 level 2");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0101 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0101 leave {}", i);
        }
        // 0b0110
        let max_c = 0b0110_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 3, "0b0110 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0110 level 1");
        assert_eq!(1, trapdoor.nodes[1].level, "0b0110 level 2");
        assert_eq!(0, trapdoor.nodes[2].level, "0b0110 level 3");
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len(), "0b0110 leaves");
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0110 leave {}", i);
        }
        // 0b0111
        let max_c = 0b0111_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1);
        assert_eq!(3, trapdoor.nodes[0].level);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len());
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i]);
        }
        // 0b1111
        let max_c = 0b1111_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1);
        assert_eq!(4, trapdoor.nodes[0].level);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len());
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i]);
        }
        // 0b1110
        let max_c = 0b1110_u32;
        let trapdoor = super::trapdoor_range(Some(0), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 4);
        assert_eq!(3, trapdoor.nodes[0].level);
        assert_eq!(2, trapdoor.nodes[1].level);
        assert_eq!(1, trapdoor.nodes[2].level);
        assert_eq!(0, trapdoor.nodes[3].level);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((max_c + 1) as usize, these_leaves.len());
        for i in 0..(max_c + 1) as usize {
            assert_eq!(leaves[i], these_leaves[i]);
        }
    }

    #[test]
    fn test_trapdoor_range_max() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let level = 4;
        let root_node = super::Node { level, k };
        let leaves = super::leaves(&Trapdoor {
            nodes: vec![root_node],
        });
        // 0b0000
        let min_c = 0b0000;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1, "0b0000 len");
        assert_eq!(4, trapdoor.nodes[0].level, "0b0000 level");
        // assert_eq!(leaves[0].k, trapdoor.nodes[0].k);
        let these_leaves = super::leaves(&trapdoor);
        assert_eq!((16 - min_c) as usize, these_leaves.len(), "0b0000 leaves");
        for i in 0..(16 - min_c) as usize {
            assert_eq!(leaves[i], these_leaves[i], "0b0000 leave {}", i);
        }
        // 0b0001
        let min_c = 0b0001_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 4, "0b0001 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0001 level 1");
        assert_eq!(1, trapdoor.nodes[1].level, "0b0001 level 2");
        assert_eq!(0, trapdoor.nodes[2].level, "0b0001 level 3");
        assert_eq!(3, trapdoor.nodes[3].level, "0b0001 level 4");
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len(), "0b0001 leaves");
        for i in 0..16 - min_c as usize {
            assert_eq!(exp_leaves[i], these_leaves[i], "0b0001 leave {}", i);
        }
        // 0b0011
        let min_c = 0b0011_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 3, "0b0011 len");
        assert_eq!(2, trapdoor.nodes[0].level, "0b0011 level 1");
        assert_eq!(0, trapdoor.nodes[1].level, "0b0011 level 2");
        assert_eq!(3, trapdoor.nodes[2].level, "0b0011 level 3");
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len(), "0b0011 leaves");
        for i in 0..(16 - min_c) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i], "0b0011 leave {}", i);
        }
        // 0b0101
        let min_c = 0b0101_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 3, "0b0101 len");
        //assert_eq!(2, trapdoor.nodes[0].level, "0b0101 level 1");
        //assert_eq!(1, trapdoor.nodes[1].level, "0b0101 level 2");
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len(), "0b0101 leaves");
        for i in 0..(16 - min_c) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i], "0b0101 leave {}", i);
        }
        // 0b0110
        let min_c = 0b0110_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 2, "0b0110 len");
        //assert_eq!(2, trapdoor.nodes[0].level, "0b0110 level 1");
        //assert_eq!(1, trapdoor.nodes[1].level, "0b0110 level 2");
        //assert_eq!(0, trapdoor.nodes[2].level, "0b0110 level 3");
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len(), "0b0110 leaves");
        for i in 0..(16 - min_c) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i], "0b0110 leave {}", i);
        }
        // 0b0111
        let min_c = 0b0111_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 2);
        //assert_eq!(3, trapdoor.nodes[0].level);
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len());
        for i in 0..(16 - min_c) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i]);
        }
        // 0b1111
        let min_c = 0b1111_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1);
        //assert_eq!(4, trapdoor.nodes[0].level);
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len());
        for i in 0..(16 - min_c) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i]);
        }
        // 0b1110
        let min_c = 0b1110_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(0b1111), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 1);
        //assert_eq!(3, trapdoor.nodes[0].level);
        //assert_eq!(2, trapdoor.nodes[1].level);
        //assert_eq!(1, trapdoor.nodes[2].level);
        //assert_eq!(0, trapdoor.nodes[3].level);
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..16].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((16 - min_c) as usize, these_leaves.len());
        for i in 0..(16 - min_c) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i]);
        }
    }

    #[test]
    fn test_trapdoor_range() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let level = 4;
        let root_node = super::Node { level, k };
        let leaves = super::leaves(&Trapdoor {
            nodes: vec![root_node],
        });
        //
        let min_c = 0b0001_u32;
        let max_c = 0b1110_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 6, "1 len");
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..=max_c as usize].to_vec();
        assert_eq!(exp_leaves.len(), these_leaves.len(), "1 exp len");
        exp_leaves.sort_unstable();
        assert_eq!((max_c - min_c + 1) as usize, these_leaves.len(), "1 leaves");
        for i in 0..(max_c - min_c + 1) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i], "1 leave {}", i);
        }
        //
        let min_c = 0b1001_u32;
        let max_c = 0b1100_u32;
        let trapdoor = super::trapdoor_range(Some(min_c), Some(max_c), None, &k, level);
        assert_eq!(trapdoor.nodes.len(), 3, "2 len");
        let mut these_leaves = super::leaves(&trapdoor);
        these_leaves.sort_unstable();
        let mut exp_leaves = leaves[min_c as usize..=max_c as usize].to_vec();
        exp_leaves.sort_unstable();
        assert_eq!((max_c - min_c + 1) as usize, these_leaves.len(), "2 leaves");
        for i in 0..(max_c - min_c + 1) as usize {
            assert_eq!(exp_leaves[i], these_leaves[i], "2 leave {}", i);
        }
    }

    #[test]
    fn test_serialization() {
        let mut cs_rng = CsRng::new();
        let mut rng = rand::thread_rng();
        let num_nodes = rng.gen_range(1..200);
        let mut nodes: Vec<Node> = Vec::with_capacity(num_nodes);
        for _i in 0..num_nodes {
            nodes.push(Node {
                level: rng.gen_range(1..10),
                k: cs_rng.random_256_bits(),
            });
        }
        let trapdoor = Trapdoor { nodes };
        let b: Vec<u8> = trapdoor.to_bytes();
        let recovered: Trapdoor =
            Trapdoor::from_bytes(b.as_slice()).expect("failed trapdoor from bytes");
        assert_eq!(num_nodes, recovered.nodes.len());
        for i in 0..num_nodes {
            assert_eq!(&(trapdoor.nodes[i]).k, &recovered.nodes[i].k);
            assert_eq!(trapdoor.nodes[i].level, recovered.nodes[i].level);
        }
    }

    #[test]
    fn bench_serialization() {
        let mut cs_rng = CsRng::new();
        let mut rng = rand::thread_rng();
        let rounds = 50_000_u128;
        debug!(
            "Bench of a trapdoor serialization/de-serialization averaged over {} rounds",
            rounds
        );
        for n in 1..11 {
            let mut nodes: Vec<Node> = Vec::with_capacity(n);
            for _i in 0..n {
                nodes.push(Node {
                    level: rng.gen_range(1..10),
                    k: cs_rng.random_256_bits(),
                });
            }
            let trapdoor = Trapdoor { nodes };
            let mut nanos_ser = 0_u128;
            let mut nanos_des = 0_u128;
            for _r in 0..rounds {
                let now = Instant::now();
                let bytes = trapdoor.to_bytes();
                nanos_ser += now.elapsed().as_nanos();
                let now = Instant::now();
                Trapdoor::from_bytes(&bytes).expect("De-serialization should have worked");
                nanos_des += now.elapsed().as_nanos();
            }
            debug!(
                "   - {} nodes: serialization/de-serialization {}/{} nanos)",
                n,
                nanos_ser / rounds,
                nanos_des / rounds,
            )
        }
    }

    #[test]
    #[ignore = "too slow for CI"]
    #[allow(unused_must_use)]
    fn bench_leaves() {
        let mut rng = CsRng::new();
        let k = rng.random_256_bits();
        let rounds = 2500_usize;
        debug!(
            "Bench of leaves generation from a node with varying depth ({} rounds per depth)",
            rounds
        );
        for level in 4..17 {
            let trapdoor = Trapdoor {
                nodes: vec![super::Node { level, k }],
            };
            let mut nanos_total = 0_u128;
            for _i in 0..rounds {
                let now = Instant::now();
                super::leaves(&trapdoor);
                nanos_total += now.elapsed().as_nanos();
            }
            debug!(
                "Average: {} nano per leave for depth: {} ({} leaves)",
                nanos_total / ((1_u128 << level) * rounds as u128),
                level,
                (1_u128 << level)
            )
        }
    }
}
