package co.topl.modifier.transaction

import co.topl.nodeView.box.GenericBox
import co.topl.nodeView.box.proposition.Proposition
import com.google.common.primitives.Longs

/**
  * Created by cykoz on 4/13/17.
  */
abstract class BoxTransaction[P <: Proposition, T, BX <: GenericBox[P, T]] extends GenericTransaction[P] {

  val newBoxes: Traversable[BX]

  override lazy val messageToSign: Array[Byte] =
    newBoxes.foldLeft(Array[Byte]())((acc, x) => acc ++ x.bytes)
    Longs.toByteArray(timestamp) ++
    Longs.toByteArray(fee)
}
