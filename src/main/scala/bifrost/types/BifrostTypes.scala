package bifrost.types

import bifrost.PersistentNodeViewModifier
import bifrost.consensus.{History, SyncInfo}
import bifrost.scorexMod.{GenericBox, GenericBoxMinimalState, GenericBoxTransaction}
import bifrost.transaction.MemoryPool
import bifrost.transaction.box.proposition.Proposition
import bifrost.transaction.wallet.Vault

trait BifrostTypes[
  T,
  P <: Proposition,
  TX <: GenericBoxTransaction[P, T, BX],
  BX <: GenericBox[P, T],
  PMOD <: PersistentNodeViewModifier[P, TX],
  SI <: SyncInfo,
  HIS <: History[P, TX, PMOD, SI, HIS],
  MS <: GenericBoxMinimalState[T, P, BX, TX, PMOD, MS],
  VL <: Vault[P, TX, PMOD, VL],
  MP <: MemoryPool[TX, MP]
] {
  type NodeView = (HIS, MS, VL, MP)
}
