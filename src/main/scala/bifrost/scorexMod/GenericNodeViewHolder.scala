package bifrost.scorexMod

import akka.actor.{Actor, ActorRef}
import bifrost.history.BifrostHistory
import bifrost.LocalInterface.{LocallyGeneratedModifier, LocallyGeneratedTransaction}
import bifrost.NodeViewModifier.{ModifierId, ModifierTypeId}
import bifrost.consensus.History.HistoryComparisonResult
import bifrost.consensus.{History, NodeViewProcessor, SyncInfo}
import bifrost.scorexMod.GenericNodeViewSynchronizer._
import bifrost.network.ConnectedPeer
import bifrost.serialization.Serializer
import bifrost.transaction.bifrostTransaction.CoinbaseTransaction
import bifrost.transaction.box.proposition.Proposition
import bifrost.transaction.wallet.Vault
import bifrost.transaction.{MemoryPool, Transaction}
import bifrost.utils.ScorexLogging
import bifrost.{NodeViewModifier, PersistentNodeViewModifier}
import scorex.crypto.encode.Base58
import bifrost.types.NodeViewTypes

import scala.collection.mutable
import scala.util.{Failure, Success}

trait GenericNodeViewHolder[
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
]
  extends NodeViewProcessor[T,P,TX,BX,PMOD,SI,HIS,MS,VL,MP] with Actor with ScorexLogging {

  import GenericNodeViewHolder._

  val networkChunkSize: Int

  var global_slot:Long = 0L

  //todo: make configurable limited size
  val modifiersCache = mutable.Map[ModifierId, (ConnectedPeer, PMOD)]()

  val subscribers = mutable.Map[GenericNodeViewHolder.EventType.Value, Seq[ActorRef]]()

  //mutable private node view instance
  private var nodeView: NodeView = restoreState().getOrElse(genesisState)

  /**
    * Hard-coded initial view all the honest nodes in a network are making progress from.
    */
  protected def genesisState: NodeView

  /**
    * Restore a local view during a node startup. If no any stored view found
    * (e.g. if it is a first launch of a node) None is to be returned
    */
  def restoreState(): Option[NodeView]

  def history(): HIS = nodeView._1

  def minimalState(): MS = nodeView._2

  def vault(): VL = nodeView._3

  def memoryPool(): MP = nodeView._4

  override def notifySubscribers[O <: NodeViewHolderEvent](eventType: EventType.Value, signal: O) =
    subscribers.getOrElse(eventType, Seq()).foreach(_ ! signal)

  def handleSubscribe: Receive = {
    case GenericNodeViewHolder.Subscribe(events) =>
      events.foreach { evt =>
        val current = subscribers.getOrElse(evt, Seq())
        subscribers.put(evt, current :+ sender())
      }
  }

  def compareViews: Receive = {
    case CompareViews(sid, modifierTypeId, modifierIds) =>
      val ids = modifierTypeId match {
        case typeId: Byte if typeId == Transaction.ModifierTypeId =>
          memoryPool().notIn(modifierIds)
        case _ =>
          modifierIds.filterNot(mid => history().contains(mid) || modifiersCache.contains(mid))
      }

      sender() ! RequestFromLocal(sid, modifierTypeId, ids)
  }

  def readLocalObjects: Receive = {
    case GetLocalObjects(sid, modifierTypeId, modifierIds) =>
      val objs: Seq[NodeViewModifier] = modifierTypeId match {
        case typeId: Byte if typeId == Transaction.ModifierTypeId =>
          memoryPool().getAll(modifierIds)
        case typeId: Byte =>
          modifierIds.flatMap(id => history().modifierById(id))
      }

      log.debug(s"Requested modifiers ${modifierIds.map(Base58.encode)}, sending: " + objs.map(_.id).map(Base58.encode))
      sender() ! ResponseFromLocal(sid, modifierTypeId, objs)
  }

  def processRemoteModifiers: Receive = {
    case ModifiersFromRemote(remote, modifierTypeId, remoteObjects) =>
      modifierCompanions.get(modifierTypeId) foreach { companion =>
        remoteObjects.flatMap(r => companion.parseBytes(r).toOption).foreach {
          case (tx: TX@unchecked) if tx.modifierTypeId == Transaction.ModifierTypeId =>
            nodeView = txModify(nodeView,tx, Some(remote))

          case pmod: PMOD@unchecked =>
            modifiersCache.put(pmod.id, remote -> pmod)
        }

        log.debug(s"Cache before(${modifiersCache.size}): ${modifiersCache.keySet.map(Base58.encode).mkString(",")}")

        var t: Option[(ConnectedPeer, PMOD)] = None
        do {
          t = {
            modifiersCache.find { case (mid, (_, pmod)) =>
              history().applicable(pmod)
            }.map { t =>
              val res = t._2
              modifiersCache.remove(t._1)
              res
            }
          }
          t.foreach { case (peer, pmod) => nodeView = pmodModify(nodeView,pmod, Some(peer)) }
        } while (t.isDefined)

        log.debug(s"Cache after(${modifiersCache.size}): ${modifiersCache.keySet.map(Base58.encode).mkString(",")}")
      }
  }

  def processLocallyGeneratedModifiers: Receive = {
    case lt: LocallyGeneratedTransaction[P, TX] =>
      nodeView = txModify(nodeView,lt.tx, None)

    case lm: LocallyGeneratedModifier[P, TX, PMOD] =>
      log.debug(s"Got locally generated modifier: ${Base58.encode(lm.pmod.id)}")
      nodeView = pmodModify(nodeView,lm.pmod, None)
  }

  def getCurrentInfo: Receive = {
    case GetCurrentView =>
      sender() ! CurrentView(history(), minimalState(), vault(), memoryPool())
  }

  def compareSyncInfo: Receive = {
    case OtherNodeSyncingInfo(remote, syncInfo: SI) =>
      log.debug(s"Comparing remote info having starting points: ${syncInfo.startingPoints.map(_._2).map(Base58.encode).toList}")
      log.debug(s"Local side contains head: ${history().contains(syncInfo.startingPoints.map(_._2).head)}")

      val extensionOpt = history().continuationIds(syncInfo.startingPoints, networkChunkSize)
      val ext = extensionOpt.getOrElse(Seq())
      val comparison = history().compare(syncInfo)
      log.debug(s"Sending extension of length ${ext.length}: ${ext.map(_._2).map(Base58.encode).mkString(",")}")
      log.debug("Comparison with Remote. Remote is: " + comparison)

      val theyAreYounger = comparison == HistoryComparisonResult.Younger
      val notSendingBlocks = extensionOpt.isEmpty

      //if(notSendingBlocks && theyAreYounger) throw new Exception("Other node was younger but we didn't have blocks to send")

      if (notSendingBlocks && theyAreYounger) {
        log.debug(s"Error: Trying to sync local node with remote node. " +
          s"Failed to find common ancestor within block history. " +
          s"Check that you are attempting to sync to the correct version of the blockchain.")
      }

      sender() ! OtherNodeSyncingStatus(
        remote,
        comparison,
        syncInfo,
        history().syncInfo(true),
        extensionOpt
      )
  }

  def getSyncInfo: Receive = {
    case GetSyncInfo =>
      sender() ! CurrentSyncInfo(history().syncInfo(false))
  }

  override def receive: Receive =
    handleSubscribe orElse
      compareViews orElse
      readLocalObjects orElse
      processRemoteModifiers orElse
      processLocallyGeneratedModifiers orElse
      getCurrentInfo orElse
      getSyncInfo orElse
      compareSyncInfo orElse {
      case a: Any => log.error(s">>>>>>>Strange input: $a :: ${a.getClass}")
    }
}


object GenericNodeViewHolder {

  case object GetSyncInfo

  case class CurrentSyncInfo[SI <: SyncInfo](syncInfo: SyncInfo)

  case object GetCurrentView

  object EventType extends Enumeration {
    //finished modifier application, successful of failed
    val FailedTransaction = Value(1)
    val FailedPersistentModifier = Value(2)
    val SuccessfulTransaction = Value(3)
    val SuccessfulPersistentModifier = Value(4)

    //starting persistent modifier application. The application could be slow
    val StartingPersistentModifierApplication = Value(5)
  }

  //a command to subscribe for events
  case class Subscribe(events: Seq[EventType.Value])

  trait NodeViewHolderEvent

  case class OtherNodeSyncingStatus[SI <: SyncInfo](peer: ConnectedPeer,
                                                    status: History.HistoryComparisonResult.Value,
                                                    remoteSyncInfo: SI,
                                                    localSyncInfo: SI,
                                                    extension: Option[Seq[(ModifierTypeId, ModifierId)]])

  //node view holder starting persistent modifier application
  case class StartingPersistentModifierApplication[P <: Proposition, TX <: Transaction[P], PMOD <: PersistentNodeViewModifier[P, TX]](modifier: PMOD) extends NodeViewHolderEvent

  //hierarchy of events regarding modifiers application outcome
  trait ModificationOutcome extends NodeViewHolderEvent {
    val source: Option[ConnectedPeer]
  }

  case class FailedTransaction[P <: Proposition, TX <: Transaction[P]]
  (transaction: TX, error: Throwable, override val source: Option[ConnectedPeer]) extends ModificationOutcome

  case class FailedModification[P <: Proposition, TX <: Transaction[P], PMOD <: PersistentNodeViewModifier[P, TX]]
  (modifier: PMOD, error: Throwable, override val source: Option[ConnectedPeer]) extends ModificationOutcome

  case class SuccessfulTransaction[P <: Proposition, TX <: Transaction[P]]
  (transaction: TX, override val source: Option[ConnectedPeer]) extends ModificationOutcome

  case class SuccessfulModification[P <: Proposition, TX <: Transaction[P], PMOD <: PersistentNodeViewModifier[P, TX]]
  (modifier: PMOD, override val source: Option[ConnectedPeer]) extends ModificationOutcome


  case class CurrentView[HIS, MS, VL, MP](history: HIS, state: MS, vault: VL, pool: MP)

}