package co.topl.nodeView.mempool

import co.topl.modifier.ModifierId
import co.topl.modifier.transaction.Transaction
import co.topl.nodeView.NodeViewComponent
import co.topl.utils.TimeProvider

import scala.math.Ordering
import scala.util.Try

/**
  * Unconfirmed transactions pool
  *
  * @tparam M -type of this memory pool
  */
trait MemoryPool[TX <: Transaction.TX, M <: MemoryPool[TX, M]]
  extends NodeViewComponent with MemPoolReader[TX] {

//  //getters
//  def modifierById(id: ModifierId): Option[TX]
//
//  def contains(id: ModifierId): Boolean

  //get ids from Seq, not presenting in mempool
  override def notIn(ids: Seq[ModifierId]): Seq[ModifierId] = ids.filter(id => !contains(id))
//
//  def getAll(ids: Seq[ModifierId]): Seq[TX]
//
//  def take[A](limit: Int)(f: UnconfirmedTx[TX] => A)(implicit ord: Ordering[A]): Iterable[UnconfirmedTx[TX]]

  //modifiers
  def put(tx: TX, time: TimeProvider.Time): Try[M]

  def put(txs: Iterable[TX], time: TimeProvider.Time): Try[M]

  def putWithoutCheck(txs: Iterable[TX], time: TimeProvider.Time): M

  def remove(tx: TX): M

  def filter(txs: Seq[TX]): M = filter(t => !txs.exists(_.id == t.id))

  def filter(condition: TX => Boolean): M

  /**
    * @return read-only copy of this state
    */
  def getReader: MemPoolReader[TX] = this
}

