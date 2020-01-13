package bifrost.consensus

import akka.actor.{Actor, ActorRef}
import bifrost.LocalInterface.{LocallyGeneratedModifier, LocallyGeneratedTransaction}
import bifrost.NodeViewModifier.{ModifierId, ModifierTypeId}
import bifrost.blocks.{BifrostBlock, BifrostBlockCompanion}
import bifrost.network.ConnectedPeer
import bifrost.scorexMod.GenericNodeViewSynchronizer._
import bifrost.scorexMod.{GenericBox, GenericBoxMinimalState, GenericBoxTransaction, GenericNodeViewHolder}
import bifrost.serialization.Serializer
import bifrost.transaction.{MemoryPool, Transaction}
import bifrost.transaction.bifrostTransaction.CoinbaseTransaction
import bifrost.transaction.box.proposition.Proposition
import bifrost.transaction.serialization.BifrostTransactionCompanion
import bifrost.transaction.wallet.Vault
import bifrost.types.BifrostTypes
import bifrost.utils.ScorexLogging
import bifrost.{NodeViewModifier, PersistentNodeViewModifier, scorexMod}
import scorex.crypto.encode.Base58

import scala.collection.mutable
import scala.util.{Failure, Success}

trait NodeViewProcessor[
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
] extends BifrostTypes[T,P,TX,BX,PMOD,SI,HIS,MS,VL,MP] with Actor with ScorexLogging {

  import scorexMod.GenericNodeViewHolder._
  import NodeViewProcessor._

  val modifierCompanions: Map[ModifierTypeId, Serializer[_ <: NodeViewModifier]] =
    Map(BifrostBlock.ModifierTypeId -> BifrostBlockCompanion,
      Transaction.ModifierTypeId -> BifrostTransactionCompanion)

  //todo: make configurable limited size
  private val modifiersCache = mutable.Map[ModifierId, (ConnectedPeer, PMOD)]()

  private def history(nodeView: NodeView): HIS = nodeView._1

  private def minimalState(nodeView: NodeView): MS = nodeView._2

  private def vault(nodeView: NodeView): VL = nodeView._3

  private def memoryPool(nodeView: NodeView): MP = nodeView._4

  private val subscribers = mutable.Map[GenericNodeViewHolder.EventType.Value, Seq[ActorRef]]()

  private def notifySubscribers[O <: NodeViewHolderEvent](eventType: EventType.Value, signal: O) =
    subscribers.getOrElse(eventType, Seq()).foreach(_ ! signal)

  private def txModify(nodeView: NodeView,tx: TX, source: Option[ConnectedPeer]):NodeView = {
    val updWallet = vault(nodeView).scanOffchain(tx)
    memoryPool(nodeView).put(tx) match {
      case Success(updPool) =>
        log.debug(s"Unconfirmed transaction $tx added to the mempool")
        notifySubscribers(EventType.SuccessfulTransaction, SuccessfulTransaction[P, TX](tx, source))
        (history(nodeView), minimalState(nodeView), updWallet, updPool)
      case Failure(e) =>
        notifySubscribers(EventType.FailedTransaction, FailedTransaction[P, TX](tx, e, source))
        nodeView
    }
  }

  //noinspection ScalaStyle
  private def pmodModify(nodeView: NodeView,pmod: PMOD, source: Option[ConnectedPeer]): NodeView = if (!history(nodeView).contains(pmod.id)) {
    notifySubscribers(
      EventType.StartingPersistentModifierApplication,
      StartingPersistentModifierApplication[P, TX, PMOD](pmod)
    )

    log.debug(s"Apply modifier to nodeViewHolder: ${Base58.encode(pmod.id)}")

    history(nodeView).append(pmod) match {
      case Success((newHistory, progressInfo)) => {
        log.debug(s"Going to apply modifications: $progressInfo")
        // Modifier is in a best chain so apply
        if (progressInfo.toApply.nonEmpty) {
          val newStateTry = if (progressInfo.rollbackNeeded) {
            minimalState(nodeView).rollbackTo(progressInfo.branchPoint.get).flatMap(_.applyModifiers(progressInfo.toApply))
          } else {
            minimalState(nodeView).applyModifiers(progressInfo.toApply)
          }
          newStateTry match {
            case Success(newMinState) => {
              val rolledBackTxs = progressInfo.toRemove.flatMap(_.transactions).flatten
              val appliedMods = progressInfo.toApply
              val appliedTxs = appliedMods.flatMap(_.transactions).flatten
              var newMemPool = memoryPool(nodeView)
              log.debug(s"${Console.GREEN}before newMemPool Size: ${newMemPool.size}${Console.RESET}")
              newMemPool = memoryPool(nodeView).putWithoutCheck(rolledBackTxs).filter { tx => !tx.isInstanceOf[CoinbaseTransaction] &&
                !appliedTxs.exists(t => t.id sameElements tx.id) && newMinState.validate(tx).isSuccess
              }
              val validUnconfirmed = newMemPool.take(100)
              log.debug(s"${Console.GREEN}Re-Broadcast unconfirmed TXs: ${validUnconfirmed.map(tx => Base58.encode(tx.id)).toList}${Console.RESET}")
              validUnconfirmed.foreach(tx => { if(tx.isInstanceOf[CoinbaseTransaction]) {log.debug(s"${Console.RED}Attempting to rebroadcast Coinbase transaction" + tx)}
                notifySubscribers(EventType.SuccessfulTransaction, SuccessfulTransaction[P, TX](tx, None))})
              log.debug(s"${Console.GREEN}newMemPool Size: ${newMemPool.size}${Console.RESET}")
              //YT NOTE - deprecate in favor of optional nodeKeys for TokenBoxRegistry - wallet boxes still being used by Forger
              //we consider that vault always able to perform a rollback needed
              val newVault = if (progressInfo.rollbackNeeded) {
                vault(nodeView).rollback(progressInfo.branchPoint.get).get.scanPersistent(appliedMods)
              } else {
                vault(nodeView).scanPersistent(appliedMods)
              }
              log.debug(s"Persistent modifier ${Base58.encode(pmod.id)} applied successfully")
              notifySubscribers(EventType.SuccessfulPersistentModifier, SuccessfulModification[P, TX, PMOD](pmod, source))
              (newHistory, newMinState, newVault, newMemPool)
            }
            case Failure(e) =>{
              val newHistoryCancelled = newHistory.drop(progressInfo.appendedId)
              log.warn(s"Can`t apply persistent modifier (id: ${Base58.encode(pmod.id)}, contents: $pmod) to minimal state", e)
              notifySubscribers(EventType.FailedPersistentModifier, FailedModification[P, TX, PMOD](pmod, e, source))
              (newHistoryCancelled, minimalState(nodeView), vault(nodeView), memoryPool(nodeView))
            }
          }
        } else {
          nodeView
        }
      }
      case Failure(e) => {
        e.printStackTrace()
        nodeView
      }
    }
  } else {
    log.warn(s"Trying to apply modifier ${Base58.encode(pmod.id)} that's already in history")
    nodeView
  }

  private def handleSubscribe: Receive = {
    case GenericNodeViewHolder.Subscribe(events) =>
      events.foreach { evt =>
        val current = subscribers.getOrElse(evt, Seq())
        subscribers.put(evt, current :+ sender())
      }
  }

  private def processModifiers: Receive = {
    case mods:NodeViewProcessorJob[NodeView,LocallyGeneratedTransaction[P,TX]] => {
      var nodeView:NodeView = mods.nodeView
      mods.job foreach { lt:LocallyGeneratedTransaction[P,TX] =>
        nodeView = txModify(nodeView,lt.tx, None)
      }
    }
    case mods:NodeViewProcessorJob[NodeView,LocallyGeneratedModifier[P,TX,PMOD]] => {
      var nodeView:NodeView = mods.nodeView
      mods.job foreach { lm:LocallyGeneratedModifier[P,TX,PMOD] =>
        log.debug(s"Got locally generated modifier: ${Base58.encode(lm.pmod.id)}")
        nodeView = pmodModify(nodeView,lm.pmod, None)
      }

    }
    case mods:NodeViewProcessorJob[NodeView,ModifiersFromRemote] => {
      var nodeView:NodeView = mods.nodeView
      mods.job foreach { modifiersFromRemote:ModifiersFromRemote =>
        val remote:ConnectedPeer = modifiersFromRemote.source
        val modifierTypeId:ModifierTypeId = modifiersFromRemote.modifierTypeId
        val remoteObjects:Seq[Array[Byte]] = modifiersFromRemote.remoteObjects
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
                history(nodeView).applicable(pmod)
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

    }
  }

  override def receive: Receive =
    handleSubscribe orElse
      processModifiers orElse {
      case a: Any => log.error(s">>>>>>>Strange input: $a :: ${a.getClass}")
    }
}


object NodeViewProcessor {

  import bifrost.scorexMod.GenericNodeViewHolder._

  trait ProcessorModifier

  case class NodeViewProcessorJob[NodeView,Job <: ProcessorModifier](nodeView:NodeView,job:Seq[Job])

  case class NodeViewProcessorResult[NodeView,Out <: ModificationOutcome](nodeView:NodeView,out:Seq[Out])
}