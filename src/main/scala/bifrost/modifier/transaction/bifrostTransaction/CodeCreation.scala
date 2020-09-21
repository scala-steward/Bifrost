package bifrost.modifier.transaction.bifrostTransaction

import java.time.Instant
import java.util.UUID

import bifrost.crypto.{FastCryptographicHash, PrivateKey25519, PrivateKey25519Companion, Signature25519}
import bifrost.modifier.box.proposition.{ProofOfKnowledgeProposition, PublicKey25519Proposition}
import bifrost.modifier.box.{Box, CodeBox}
import bifrost.modifier.transaction.bifrostTransaction.AssetCreation.syntacticValidate
import bifrost.modifier.transaction.bifrostTransaction.Transaction.Nonce
import bifrost.modifier.transaction.serialization.CodeBoxCreationSerializer
import bifrost.program.ProgramPreprocessor
import bifrost.state.{State, StateReader}
import bifrost.utils.serialization.BifrostSerializer
import bifrost.wallet.Wallet
import com.google.common.primitives.{Bytes, Longs}
import io.circe.syntax._
import io.circe.{Json, JsonObject}
import scorex.crypto.encode.Base58

import scala.util.{Failure, Success, Try}

case class CodeCreation(to: PublicKey25519Proposition,
                        signature: Signature25519,
                        code: String,
                        override val fee: Long,
                        override val timestamp: Long,
                        data: String) extends Transaction {

  override type M = CodeCreation

  lazy val serializer: BifrostSerializer[CodeCreation] = CodeBoxCreationSerializer

  override def toString: String = s"CodeCreation(${json.noSpaces})"

  override lazy val boxIdsToOpen: IndexedSeq[Array[Byte]] = IndexedSeq()

  lazy val hashNoNonces: Array[Byte] = FastCryptographicHash(
    to.pubKeyBytes ++
      code.getBytes ++
      Longs.toByteArray(fee) ++
      Longs.toByteArray(timestamp)
  )

  override val newBoxes: Traversable[Box] = {

    val nonce = CodeCreation.nonceFromDigest(FastCryptographicHash(
      "CodeCreation".getBytes ++
        to.pubKeyBytes ++
        code.getBytes ++
        hashNoNonces
    ))

    val uuid = UUID.nameUUIDFromBytes(CodeBox.idFromBox(to, nonce))

    val interface = ProgramPreprocessor("code", code)(JsonObject.empty).interface

    Seq(CodeBox(to, nonce, uuid, Seq(code), interface))
  }

  override lazy val json: Json = Map(
    "txHash" -> id.toString.asJson,
    "txType" -> "CodeCreation".asJson,
    "newBoxes" -> newBoxes.map(b => Base58.encode(b.id).asJson).toSeq.asJson,
    "to" -> Base58.encode(to.pubKeyBytes).asJson,
    "signature" -> Base58.encode(signature.signature).asJson,
    "code" -> code.asJson,
    "fee" -> fee.asJson,
    "timestamp" -> timestamp.asJson,
    "data" -> data.asJson
  ).asJson

  override lazy val messageToSign: Array[Byte] = Bytes.concat(
    "CodeCreation".getBytes,
    to.pubKeyBytes,
    newBoxes.foldLeft(Array[Byte]())((a, b) => a ++ b.bytes),
    code.getBytes,
    Longs.toByteArray(fee),
    data.getBytes
  )
}

object CodeCreation {

  type SR = StateReader[Box, ProofOfKnowledgeProposition[PrivateKey25519], Any]

  def nonceFromDigest(digest: Array[Byte]): Nonce = Longs.fromByteArray(digest.take(Longs.BYTES))

  def createAndApply(w: Wallet,
                     to: PublicKey25519Proposition,
                     code: String,
                     fee: Long,
                     data: String): Try[CodeCreation] = Try {

    val selectedSecret = w.secretByPublicImage(to).get
    val fakeSig = Signature25519(Array())
    val timestamp = Instant.now.toEpochMilli
    val messageToSign = CodeCreation(to, fakeSig, code, fee, timestamp, data).messageToSign

    val signature = PrivateKey25519Companion.sign(selectedSecret, messageToSign)

    CodeCreation(to, signature, code, fee, timestamp, data)
  }

  def syntacticValidate(tx: CodeCreation, withSigs: Boolean = true): Try[Unit] = Try {
    require(tx.fee >= 0)
    require(tx.timestamp >= 0)
    require(tx.signature.isValid(tx.to, tx.messageToSign), "Invalid signature")

    tx.newBoxes.size match {
      //only one box should be created
      case 1 if (tx.newBoxes.head.isInstanceOf[CodeBox]) => Success(Unit)
      case _ => Failure(new Exception("Invlid transaction"))
    }
  }

  def validatePrototype(tx: CodeCreation): Try[Unit] = syntacticValidate(tx, withSigs = false)

  /**
    * Check the code is valid chain code and the newly created CodeBox is
    * formed properly
    *
    * @param tx : CodeCreation transaction
    * @return
    */
  def semanticValidate(tx: CodeCreation, state: SR): Try[Unit] = {

    // check that the transaction is correctly formed before checking state
    syntacticValidate(tx)

  }
}
