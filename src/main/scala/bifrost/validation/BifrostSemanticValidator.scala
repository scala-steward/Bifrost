package bifrost.validation

import bifrost.blocks.{BifrostBlock, BifrostBlockCompanion}
import bifrost.forging.{Forger, ForgingSettings}
import bifrost.history.BifrostStorage
import bifrost.block.BlockValidator
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper

import scala.util.Try

class BifrostSemanticValidator(storage: BifrostStorage, settings: ForgingSettings) extends BlockValidator[BifrostBlock] {

  def validate(block: BifrostBlock): Try[Unit] = checkBlockHash(block)

  private def checkBlockHash(block: BifrostBlock): Try[Unit] = Try {
    if (!storage.isGenesis(block)) {
      require(
        ByteArrayWrapper(block.id) ==
          ByteArrayWrapper(FastCryptographicHash(BifrostBlockCompanion.toBytes(block)))
      )
    }
  }
}

