package bifrost.validation

import bifrost.blocks.{BifrostBlock, BifrostBlockCompanion}
import bifrost.forging.{Forger, ForgingSettings}
import bifrost.history.BifrostStorage
import bifrost.block.BlockValidator
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper

import scala.util.Try

class BifrostBlockValidator(storage: BifrostStorage, settings: ForgingSettings) extends BlockValidator[BifrostBlock] {

  def validate(block: BifrostBlock): Try[Unit] = checkConsensusRules(block)

  //PoS consensus rules checks, throws exception if anything wrong
  private def checkConsensusRules(block: BifrostBlock): Try[Unit] = Try {
    if (!storage.isGenesis(block)) {
      storage.heightOf(block.parentId) match {
        case Some(x) if x+1 < settings.forkHeight_3x => {
          val lastBlock = storage.modifierById(block.parentId).get
          val hit = Forger.hit(lastBlock)(block.forgerBox)
          val difficulty = storage.difficultyOf(block.parentId).get
          val target = Forger.calcAdjustedTarget(difficulty, lastBlock, storage.settings.targetBlockTime.length)
          require(BigInt(hit) < target * BigInt(block.forgerBox.value), s"$hit < $target failed, $difficulty, ")
        }
        case _ => {

        }
      }
    }
  }
}
