package crypto

import attestation.Evidence
import io.circe.{Decoder, Encoder, HCursor}
import io.circe.syntax.EncoderOps

case class Transaction(newBoxes: Seq[NewBox], boxesToRemove: Option[Seq[String]])

object Transaction {

  implicit val txDecoder: Decoder[Transaction] = (hCursor: HCursor) => {
    for {
      newBoxes <- hCursor.downField("newBoxes").as[Seq[NewBox]]
      boxesToRemove <- hCursor.downField("boxesToRemove").as[Option[Seq[String]]]
    } yield Transaction(newBoxes, boxesToRemove)
  }

  implicit val txEncoder: Encoder[Transaction] = (tx: Transaction) =>
    Map(
      "newBoxes" -> tx.newBoxes.asJson,
      "boxesToRemove" -> tx.boxesToRemove.asJson
    ).asJson

}

case class NewBox(evidence: Evidence,
                  nonce: String,
                  id: String,
                  typeOfBox: String,
                  value: TokenValueHolder)

object NewBox {
  implicit val newBoxEncoder: Encoder[NewBox] = (box: NewBox) =>
    Map(
      "id" -> box.id.asJson,
      "type" -> box.typeOfBox.asJson,
      "evidence" -> box.evidence.toString.asJson,
      "value" -> box.value.asJson,
      "nonce" -> box.nonce.asJson
    ).asJson

  implicit val newBoxDecoder: Decoder[NewBox] = (hCursor: HCursor) => {
    for {
      nonce <- hCursor.downField("nonce").as[String]
      id <- hCursor.downField("id").as[String]
      typeOfBox <- hCursor.downField("type").as[String]
      evidence <- hCursor.downField("evidence").as[Evidence]
      value <- hCursor.downField("value").as[TokenValueHolder]
    } yield NewBox(evidence, nonce, id, typeOfBox, value)
  }
}
