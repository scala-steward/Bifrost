package bifrost.validation

import bifrost.blocks.{BifrostBlock, BifrostBlockCompanion}
import bifrost.forging.{Forger, ForgingSettings}
import bifrost.history.BifrostStorage
import bifrost.block.BlockValidator
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper
import scorex.crypto.signatures.Curve25519
import bifrost.consensus.ouroboros.{Kes, Sig}

import scala.util.Try

class BifrostSignatureValidator(storage: BifrostStorage, settings: ForgingSettings) extends BlockValidator[BifrostBlock] {

  val ed25519 = new Sig
  val kes25519 = new Kes

  def validate(block: BifrostBlock): Try[Unit] = checkBlockSig(block)

  private def checkBlockSig(block: BifrostBlock): Try[Unit] = Try {
    if (!storage.isGenesis(block)) {
      storage.heightOf(block.parentId) match {
        case Some(x) if x+1 < settings.forkHeight_3x => {
          require(
            Curve25519.verify(block.signature.signature,block.oldSigningBytes,block.forgerBox.proposition.pubKeyBytes)
          )
        }
        case _ => {
          require(
            ed25519.verify(block.signature.signature,BifrostBlockCompanion.messageToSign(block),block.ouroborosCertificate.get_PK_SIG) &&
            kes25519.verify(block.ouroborosCertificate.get_PK_KES,BifrostBlockCompanion.messageToSign(block),block.kesSignature,block.ouroborosCertificate.get_slot)
          )
        }
      }
    }
  }
}