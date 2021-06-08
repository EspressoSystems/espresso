sig Transaction {
	nextTxn:       lone Transaction,
	txnNullifiers: set Nullifier,
	txnNewRecords: set Record
}

pred liveRecord[r: Record, t: Transaction] {
    r in t.(^~nextTxn).txnNewRecords
}

fact {
    all n: Nullifier |
		one (n.(~txnNullifiers)) &&
    	(one (n.~nullifier)) &&
    	(liveRecord[n.~nullifier,n.(~txnNullifiers)])
}

//nextOp: Operation -> lone Operation

sig AssetType {}

sig Nullifier {}

abstract sig Nullifiable {
	nullifier: lone Nullifier
}

sig DefinableAsset extends Nullifiable {
    assetType: AssetType
} { no t: Transaction | this in t.txnNewRecords }

sig IssuableAsset extends Nullifiable {
	issDefn: DefinableAsset,
	issTotal: Int
}

fact {
	all iss: IssuableAsset |
    one t: Transaction |
		iss in t.txnNewRecords &&
		((iss.issDefn in (t.txnNullifiers.~nullifier)
		  && iss.issCount = 0
	     ) ||
		 (one prevIss: IssuableAsset
		   | prevIss.nullifier in t.txnNullifiers
			 && iss.issDefn = prevIss.issDefn
		     && (let rec = (t.txnNewRecords
							& iss.issDefn.assetType.(~recType))
				 | )
			 && iss.issCount = (prevIss.issCount+1)))
}

sig Record extends Nullifiable {
	recType: AssetType,
	recAmount: Int
}

fact {
	all r: Nullifiable
	| r.nullifier.(~nullifier) = r
}

/*
nextOp: Operation -> Operation
~nextOp
^nextOp
*nextOp
*/

fact { lone o: Transaction | no (o.~nextTxn) }
fact { all o: Transaction | o not in o.^nextTxn }
fact { some (Transaction.nextTxn) }


check SelfLoop { no o: Transaction | o in o.nextTxn }

pred twoOps { #Transaction = 3 }

//run SelfLoop

run twoOps for 8 expect 1

