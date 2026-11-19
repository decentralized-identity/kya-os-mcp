import { describe, expect, it } from "vitest";
import { MemoryDelegationGraphStorage } from "../memory-graph-storage.js";
import { statusEntryKey, type DelegationNode } from "../../delegation-graph.js";

const LIST = "https://status.example/revocation/v1";

const node = (id: string, entry: Partial<DelegationNode> = {}): DelegationNode => ({
  id,
  parentId: null,
  children: [],
  issuerDid: "did:web:issuer.example",
  subjectDid: `did:web:${id}.example`,
  ...entry,
});

const structured = (statusListIndex: unknown) => ({
  credentialStatus: {
    type: "StatusList2021Entry" as const,
    statusPurpose: "revocation" as const,
    statusListIndex: statusListIndex as string,
    statusListCredential: LIST,
  },
});

describe("statusEntryKey", () => {
  it("names the entry revocation sets, its index in canonical decimal, whichever field carries it", () => {
    expect(statusEntryKey(node("a", structured("3")))).toBe(`${LIST}#3`);
    expect(statusEntryKey(node("b", structured("003")))).toBe(`${LIST}#3`);
    expect(statusEntryKey(node("c", structured(3)))).toBe(`${LIST}#3`);
    expect(statusEntryKey(node("d", { credentialStatusId: `${LIST}#3` }))).toBe(`${LIST}#3`);
    // The structured entry is the one revocation sets, so it names the key.
    expect(statusEntryKey(node("e", { ...structured("4"), credentialStatusId: `${LIST}#3` }))).toBe(`${LIST}#4`);
  });

  it("is undefined for a node with no entry to set, and throws for an index no list can hold", () => {
    expect(statusEntryKey(node("a"))).toBeUndefined();
    expect(statusEntryKey(node("b", { credentialStatusId: "urn:uuid:4b1c0c56-7f0e-4c32-9b8e-0b1a2c3d4e5f" }))).toBeUndefined();
    expect(() => statusEntryKey(node("c", structured("3a")))).toThrow('Invalid statusListIndex "3a"');
  });
});

describe("MemoryDelegationGraphStorage.getNodeIdsByStatusEntry", () => {
  it("finds every stored node registered with an entry, as it reads now", async () => {
    const storage = new MemoryDelegationGraphStorage();
    for (const stored of [
      node("a", structured("3")),
      node("b", { credentialStatusId: `${LIST}#3` }),
      node("c", structured(3)),
      node("d", structured("4")),
      node("e", { credentialStatusId: "urn:uuid:4b1c0c56-7f0e-4c32-9b8e-0b1a2c3d4e5f" }),
      node("f"),
    ]) {
      await storage.setNode(stored);
    }

    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#3`)).toEqual(["a", "b", "c"]);
    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#4`)).toEqual(["d"]);
    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#5`)).toEqual([]);

    await storage.deleteNode("b");
    await storage.setNode(node("c", structured("5")));
    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#3`)).toEqual(["a"]);
    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#5`)).toEqual(["c"]);

    storage.clear();
    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#3`)).toEqual([]);
  });

  it("lets a node be registered again with its own entry, and another be registered with an entry no node has", async () => {
    const storage = new MemoryDelegationGraphStorage();
    await storage.registerNodeAtomic(node("a", structured("3")));
    await storage.registerNodeAtomic(node("a", structured("3")));
    await storage.registerNodeAtomic(node("b", structured("4")));

    expect(await storage.getNodeIdsByStatusEntry(`${LIST}#3`)).toEqual(["a"]);
    await expect(storage.registerNodeAtomic(node("c", structured("03")))).rejects.toThrow(
      `Delegation c cannot be registered with status list entry ${LIST}#3: the entry is registered to another delegation`,
    );
  });
});
