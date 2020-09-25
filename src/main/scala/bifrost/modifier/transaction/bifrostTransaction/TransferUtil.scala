package bifrost.modifier.transaction.bifrostTransaction

import bifrost.crypto.{ PrivateKey25519, PrivateKey25519Companion, Signature25519 }
import bifrost.modifier.box._
import bifrost.modifier.box.proposition.PublicKey25519Proposition
import bifrost.modifier.transaction.bifrostTransaction.Transaction.{ Nonce, Value }
import bifrost.state.TokenBoxRegistry
import bifrost.wallet.Wallet
import com.google.common.primitives.Longs
import io.iohk.iodb.ByteArrayWrapper
import scorex.crypto.encode.Base58

import scala.util.Try

trait TransferUtil {

  def nonceFromDigest ( digest: Array[Byte] ): Nonce = Longs.fromByteArray(digest.take(Longs.BYTES))

  def parametersForApply ( from: IndexedSeq[(PrivateKey25519, Nonce)],
                           to: IndexedSeq[(PublicKey25519Proposition, Value)],
                           fee: Long,
                           timestamp: Long,
                           txType   : String,
                           extraArgs: Any*
                         ):
  Try[(IndexedSeq[(PublicKey25519Proposition, Nonce)], Map[PublicKey25519Proposition, Signature25519])] = Try {
    val fromPub = from.map { case (pr, n) => pr.publicImage -> n }

    val undersigned = txType match {
      case "PolyTransfer"  => PolyTransfer(fromPub, to, Map(), fee, timestamp, extraArgs(0).asInstanceOf[String])
      case "ArbitTransfer" => ArbitTransfer(fromPub, to, Map(), fee, timestamp, extraArgs(0).asInstanceOf[String])
      case "AssetTransfer" => AssetTransfer(fromPub,
                                            to,
                                            Map(),
                                            extraArgs(0).asInstanceOf[PublicKey25519Proposition],
                                            extraArgs(1).asInstanceOf[String],
                                            fee,
                                            timestamp,
                                            extraArgs(2).asInstanceOf[String]
                                            )
    }

    val msg = undersigned.messageToSign
    val sigs = from.map { case (priv, _) => (priv.publicImage, PrivateKey25519Companion.sign(priv, msg)) }.toMap
    (fromPub, sigs)
  }


  //YT Note - for transactions generated by node's keys -
  // sent to parametersToApply for further sanitation before tx creation

  //noinspection ScalaStyle
  def parametersForCreate ( tbr: TokenBoxRegistry,
                            w: Wallet,
                            toReceive: IndexedSeq[(PublicKey25519Proposition, Long)],
                            sender   : IndexedSeq[PublicKey25519Proposition],
                            fee      : Long,
                            txType   : String,
                            extraArgs: Any*
                          ):
  (IndexedSeq[(PrivateKey25519, Long, Long)], IndexedSeq[(PublicKey25519Proposition, Long)]) = {

    toReceive
      .foldLeft((IndexedSeq[(PrivateKey25519, Long, Long)](), IndexedSeq[(PublicKey25519Proposition, Long)]())) {
        case (a, (recipient, amount)) =>

          // Restrict box search to specified public keys if provided
          val keyFilteredBoxes: Seq[Box] = sender.flatMap(s =>
                                                            tbr.boxesByKey(s))

          // Match only the type of boxes specified by txType
          val keyAndTypeFilteredBoxes: Seq[TokenBox] = txType match {
            case "PolyTransfer"  =>
              keyFilteredBoxes.flatMap(_ match {
                                         case p: PolyBox => Some(p)
                                         case _          => None
                                       })
            case "ArbitTransfer" =>
              keyFilteredBoxes.flatMap(_ match {
                                         case a: ArbitBox => Some(a)
                                         case _           => None
                                       })
            case "AssetTransfer" =>
              if ( extraArgs(2).asInstanceOf[Option[String]].isDefined ) {
                keyFilteredBoxes.flatMap(_ match {
                                           case a: AssetBox
                                             if (Base58.encode(a.id) equals extraArgs(2).asInstanceOf[Option[String]].get) =>
                                             Some(a)
                                         })
              } else {
                keyFilteredBoxes.flatMap(_ match {
                                           case a: AssetBox
                                             if (a.assetCode equals extraArgs(1).asInstanceOf[String]) &&
                                               (a.issuer equals extraArgs(0)
                                                 .asInstanceOf[PublicKey25519Proposition]) =>
                                             Some(a)
                                           case _                                          => None
                                         })
              }
          }

          if ( keyAndTypeFilteredBoxes.length < 1 ) throw new Exception("No boxes found to fund transaction")

          //YT Note - Dust collection takes place here - so long as someone forms a valid transaction,
          //YT Note - all their tokens of that type are collected into one spend box and one change box

          // Check if the keys currently unlocked in wallet match the proposition of any of the found boxes
          val senderInputBoxes: IndexedSeq[(PrivateKey25519, Long, Long)] = keyAndTypeFilteredBoxes
            .flatMap {
              b =>
                w.secretByPublicImage(b.proposition)
                  .map((_, b.nonce, b.value))
            }
            .toIndexedSeq

          // amount available to send in tx
          val canSend = senderInputBoxes.map(_._3).sum

          if ( canSend < amount + fee ) throw new Exception("Not enough funds to create transaction")

          // Updated sender balance for specified box type (this is the change calculation for sender)
          val senderUpdatedBalance: (PublicKey25519Proposition, Long) = (sender.head, canSend - amount - fee)

          // create the list of outputs (senderChangeOut & recipientOut)
          val to: IndexedSeq[(PublicKey25519Proposition, Long)] = IndexedSeq(senderUpdatedBalance, (recipient, amount))

          require(senderInputBoxes.map(_._3).sum - to.map(_._2).sum == fee)
          (a._1 ++ senderInputBoxes, a._2 ++ to)
      }
  }

  //YT Note - for prototype transactions that don't need to be signed by node's wallet

  //noinspection ScalaStyle
  def parametersForCreate ( tbr: TokenBoxRegistry,
                            toReceive: IndexedSeq[(PublicKey25519Proposition, Long)],
                            sender   : IndexedSeq[PublicKey25519Proposition],
                            fee      : Long,
                            txType   : String,
                            extraArgs: Any*
                          ):
  (IndexedSeq[(PublicKey25519Proposition, Long, Long)], IndexedSeq[(PublicKey25519Proposition, Long)]) = {

    toReceive
      .foldLeft((IndexedSeq[(PublicKey25519Proposition, Long, Long)](), IndexedSeq[(PublicKey25519Proposition, Long)]())) {
        case (a, (recipient, amount)) =>

          // Restrict box search to specified public keys if provided
          val keyFilteredBoxes: Seq[Box] = sender.flatMap(s =>
                                                            tbr.boxesByKey(s))

          // Match only the type of boxes specified by txType
          val keyAndTypeFilteredBoxes: Seq[TokenBox] = txType match {
            case "PolyTransfer"  =>
              keyFilteredBoxes.flatMap(_ match {
                                         case p: PolyBox => Some(p)
                                         case _          => None
                                       })
            case "ArbitTransfer" =>
              keyFilteredBoxes.flatMap(_ match {
                                         case a: ArbitBox => Some(a)
                                         case _           => None
                                       })
            case "AssetTransfer" =>
              if ( extraArgs(2).asInstanceOf[Option[String]].isDefined ) {
                keyFilteredBoxes.flatMap(_ match {
                                           case a: AssetBox
                                             if (Base58.encode(a.id) equals extraArgs(2).asInstanceOf[Option[String]].get) =>
                                             Some(a)
                                         })
              } else {
                keyFilteredBoxes.flatMap(_ match {
                                           case a: AssetBox
                                             if (a.assetCode equals extraArgs(1).asInstanceOf[String]) &&
                                               (a.issuer equals extraArgs(0)
                                                 .asInstanceOf[PublicKey25519Proposition]) =>
                                             Some(a)
                                           case _                                          => None
                                         })
              }
          }

          if ( keyAndTypeFilteredBoxes.length < 1 ) throw new Exception("No boxes found to fund transaction")

          val senderInputBoxes: IndexedSeq[(PublicKey25519Proposition, Nonce, Long)] = keyAndTypeFilteredBoxes
            .map(b => (b.proposition, b.nonce, b.value))
            .toIndexedSeq

          // amount available to send in tx
          val canSend = senderInputBoxes.map(_._3).sum

          if ( canSend < amount + fee ) throw new Exception("Not enough funds to create transaction")

          require(canSend >= (toReceive.map(_._2).sum + fee))

          // Updated sender balance for specified box type (this is the change calculation for sender)
          //TODO reconsider? - returns change to first key in list
          val senderUpdatedBalance: (PublicKey25519Proposition, Long) = (sender.head, canSend - amount - fee)

          // create the list of outputs (senderChangeOut & recipientOut)
          val to: IndexedSeq[(PublicKey25519Proposition, Long)] = IndexedSeq(senderUpdatedBalance, (recipient, amount))

          require(senderInputBoxes.map(_._3).sum - to.map(_._2).sum == fee)
          (a._1 ++ senderInputBoxes, a._2 ++ to)
      }
  }

  def validateTx ( tx: TransferTransaction ): Try[Unit] = Try {
    require(tx.to.forall(_._2 >= 0L))
    require(tx.fee >= 0)
    require(tx.timestamp >= 0)
    require(tx.signatures.forall {
      case (prop, sign) => sign.isValid(prop, tx.messageToSign)
    })
    require(tx.from.forall {
      case (prop, nonce) => tx.signatures.contains(prop)
    })
    val wrappedBoxIdsToOpen = tx.boxIdsToOpen.map(b ⇒ ByteArrayWrapper(b))
    require(tx.newBoxes.forall(b ⇒ !wrappedBoxIdsToOpen.contains(ByteArrayWrapper(b.id))))
  }

  def validateTxWithoutSignatures ( tx: TransferTransaction ): Try[Unit] = Try {
    require(tx.to.forall(_._2 >= 0L))
    require(tx.fee >= 0)
    require(tx.timestamp >= 0)
    val wrappedBoxIdsToOpen = tx.boxIdsToOpen.map(b ⇒ ByteArrayWrapper(b))
    require(tx.newBoxes.forall(b ⇒ !wrappedBoxIdsToOpen.contains(ByteArrayWrapper(b.id))))
  }
}
