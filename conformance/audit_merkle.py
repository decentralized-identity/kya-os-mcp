"""The audit trail's RFC 9162 Merkle tree: its root, and its inclusion and consistency proofs.

Leaves and nodes are hashed apart, under the 0x00 and 0x01 prefixes RFC 9162 gives them.
"""

from digests import sha256_digest


def digest_bytes(value: str) -> bytes:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise ValueError("invalid sha256 digest")
    return bytes.fromhex(value[len(prefix):])


def audit_leaf_hash(value: str) -> str:
    return sha256_digest(b"\x00" + digest_bytes(value))


def audit_node_hash(left: str, right: str) -> str:
    material = b"\x01" + digest_bytes(left) + digest_bytes(right)
    return sha256_digest(material)


def audit_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256_digest(b"")
    if len(leaves) == 1:
        return audit_leaf_hash(leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return audit_node_hash(audit_root(leaves[:split]), audit_root(leaves[split:]))


def audit_verify_inclusion(leaf: str, index: int, size: int, root: str, path: list[str]) -> bool:
    if size <= 0 or index < 0 or index >= size:
        return False
    leaf_pos, last_pos = index, size - 1
    calculated = audit_leaf_hash(leaf)
    for sibling in path:
        if last_pos == 0:
            return False
        if leaf_pos & 1 or leaf_pos == last_pos:
            calculated = audit_node_hash(sibling, calculated)
            while leaf_pos != 0 and not leaf_pos & 1:
                leaf_pos //= 2
                last_pos //= 2
        else:
            calculated = audit_node_hash(calculated, sibling)
        leaf_pos //= 2
        last_pos //= 2
    return last_pos == 0 and calculated == root


def audit_verify_consistency(old_size: int, new_size: int, old_root: str,
                             new_root: str, path: list[str]) -> bool:
    if old_size <= 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return not path and old_root == new_root
    old_node, new_node = old_size - 1, new_size - 1
    while old_node & 1:
        old_node //= 2
        new_node //= 2
    path_index = 0
    if old_node == 0:
        old_calculated = new_calculated = old_root
    else:
        if not path:
            return False
        old_calculated = new_calculated = path[0]
        path_index = 1
    for sibling in path[path_index:]:
        if new_node == 0:
            return False
        if old_node & 1 or old_node == new_node:
            old_calculated = audit_node_hash(sibling, old_calculated)
            new_calculated = audit_node_hash(sibling, new_calculated)
            while old_node != 0 and not old_node & 1:
                old_node //= 2
                new_node //= 2
        else:
            new_calculated = audit_node_hash(new_calculated, sibling)
        old_node //= 2
        new_node //= 2
    return (new_node == 0 and old_calculated == old_root and
            new_calculated == new_root)
