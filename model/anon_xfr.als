sig Hashable {}

sig NumHash {
    numhash_val: disj Int,
    numhash_hash: disj Hashable
}

sig ZeroHash {
    zerohash: Hashable,
} { zerohash = 0.~numhash_val.numhash_hash }

fact { one ZeroHash }

sig CommHash {
    commhash_val: disj RecordCommitment,
    commhash_hash: disj Hashable
}

sig Hash4Key {
    keyIx: disj Int
}

sig Hash4 {
    h4_key: Hash4Key,
    h4_in1: Hashable,
    h4_in2: Hashable,
    h4_in3: Hashable,
    h4_out: Hashable
}

fact "CRHF" {
    all h: Hashable | all in1,in2: h.~h4_out |
        in1 = in2 || in1.h4_key != in2.h4_key
}

pred hashOf[k_ix: Int, in1,in2,in3, out: Hashable] {
  some h: Hash4 {
       out = h.h4_out
    && h.h4_in1 = in1
    && h.h4_in2 = in2
    && h.h4_in3 = in3
    && h.h4_key = k_ix.~keyIx
  }
}

abstract sig MerkleNode {
    merkleLevel: Int,
    merkleChildren: set MerkleNode,
    merkleHash: Hashable
} { merkleLevel >= 0
    && this not in this.^@merkleChildren
    //&& all c: merkleChildren | c.@merkleLevel + 1 = merkleLevel
    && all c: merkleChildren | plus[c.@merkleLevel,1] = merkleLevel
    //&& all c: merkleChildren | c.@merkleLevel = merkleLevel
    }

sig Nullifier {}

sig RecordCommitment {
    recNullifier: lone Nullifier
} { one this.~merkleVal && lone recNullifier.~@recNullifier }

fact { all n: Nullifier | one n.~recNullifier }
fact { all r: RecordCommitment | one (r.~commhash_val) }

sig MerkleLeaf extends MerkleNode {
    merkleUid: Int,
    merkleVal: RecordCommitment
} { merkleLevel = 0 && merkleChildren = none && merkleUid >= 0
    && hashOf[0, merkleUid.~numhash_val.numhash_hash,
              merkleVal.~commhash_val.commhash_hash,
              ZeroHash.zerohash,
              merkleHash]
    }

pred nextUids[lo: set MerkleNode, hi: set MerkleNode] {
    // everything in lo has a lower uid than in hi
    (all lv: lo.*merkleChildren.merkleUid |
     all hv: hi.*merkleChildren.merkleUid | lv < hv)
    && (// the lowest uid in hi is (highest in lo) + 1
        (no hi.*merkleChildren.merkleUid)
        || some lowest_hv: hi.*merkleChildren.merkleUid {
            minus[lowest_hv,1] in lo.*merkleChildren.merkleUid
        })
}

sig MerkleBranch extends MerkleNode {
    merkleLeft:  lone MerkleNode,
    merkleMid:   lone MerkleNode,
    merkleRight: lone MerkleNode
} {  (merkleChildren = (merkleLeft + merkleMid + merkleRight))
  && nextUids[merkleLeft,merkleMid]
  && nextUids[merkleMid,merkleRight]
  && (some ((this.^@merkleChildren) & MerkleLeaf))
  // left filling
  && ((some merkleRight) => some merkleMid)
  && ((some merkleMid) => some merkleLeft)
  // hash
  && hashOf[merkleLevel,
            merkleLeft.@merkleHash,
            merkleMid.@merkleHash,
            merkleRight.@merkleHash,
            merkleHash]
  }

//sig AnonXfr {
//    xfrNext: lone AnonXfr,
//    xfrNullifiers: set Nullifier,
//    xfrNewRecords: set RecordCommitment
//} {
//       xfrNullifiers.~@xfrNullifiers = this
//    && xfrNewRecords.~@xfrNewRecords = this
//    && xfrNext.~@xfrNext = this
//    && xfrNullifiers.~recNullifier <= this.^~@xfrNext.@xfrNewRecords
//}
//
//fact { one xfr: AnonXfr | no xfr.~xfrNext }

//fact { one n: MerkleNode | no (n.~merkleChildren) }

fact { all n: MerkleNode |
    (no (n.~merkleChildren)) => (0 in n.*merkleChildren.merkleUid) }

run { some MerkleBranch } for 4 expect 1
run { #MerkleLeaf > 2 } for 4 but 5 Int,6 MerkleNode expect 1
run { #MerkleLeaf > 9 } for 4 but 5 Int,15 MerkleNode expect 1




