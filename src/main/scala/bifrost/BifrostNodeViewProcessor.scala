package bifrost

import bifrost.blocks.{BifrostBlock, BifrostBlockCompanion}
import bifrost.forging.ForgingSettings
import bifrost.history.{BifrostHistory, BifrostSyncInfo}
import bifrost.mempool.BifrostMemPool
import bifrost.scorexMod.GenericNodeViewHolder
import bifrost.state.BifrostState
import bifrost.transaction.box.{ArbitBox, BifrostBox}
import bifrost.wallet.BWallet
import bifrost.NodeViewModifier
import bifrost.NodeViewModifier.ModifierTypeId
import bifrost.serialization.Serializer
import bifrost.transaction.Transaction
import bifrost.transaction.bifrostTransaction.{ArbitTransfer, BifrostTransaction, PolyTransfer}
import bifrost.transaction.box.proposition.{ProofOfKnowledgeProposition, PublicKey25519Proposition}
import bifrost.transaction.serialization.BifrostTransactionCompanion
import bifrost.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import bifrost.utils.ScorexLogging
import scorex.crypto.encode.Base58
import bifrost.consensus.NodeViewProcessor

class BifrostNodeViewProcessor(settings: ForgingSettings)
  extends NodeViewProcessor[
    Any,
    ProofOfKnowledgeProposition[PrivateKey25519],
    BifrostTransaction,
    BifrostBox,
    BifrostBlock,
    BifrostSyncInfo,
    BifrostHistory,
    BifrostState,
    BWallet,
    BifrostMemPool
  ] {

}
