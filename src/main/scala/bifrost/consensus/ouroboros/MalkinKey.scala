package bifrost.consensus.ouroboros

class MalkinKey {
  private var L:Tree[Array[Byte]] = Leaf(Array())
  private var Si:Tree[Array[Byte]] = Leaf(Array())
  private var sig:Array[Byte] = Array()
  private var pki:Array[Byte] = Array()
  private var rp:Array[Byte] = Array()

  def update(kes:Kes,step:Long) = {
    val updatedKey = kes.updateKey((L,Si,sig,pki,rp),step)
    L = updatedKey._1
    Si = updatedKey._2
    sig = updatedKey._3
    pki = updatedKey._4
    rp = updatedKey._5
  }

  def sign(kes:Kes,m:Array[Byte]): (Array[Byte],Array[Byte],Array[Byte]) = {
    kes.sign((L,Si,sig,pki,rp),m)
  }

  def getPublic(kes:Kes):Array[Byte] = {
    kes.publicKey((L,Si,sig,pki,rp))
  }

  def time(kes:Kes):Long = {
    kes.getKeyTimeStep((L,Si,sig,pki,rp))
  }

}

object MalkinKey {
  def apply(kes:Kes,seed:Array[Byte],step:Long):MalkinKey = {
    val keyData = kes.generateKey(seed)
    val updatedKeyData = kes.updateKey(keyData,step)
    val newKey = new MalkinKey
    newKey.L = updatedKeyData._1
    newKey.Si = updatedKeyData._2
    newKey.sig = updatedKeyData._3
    newKey.pki = updatedKeyData._4
    newKey.rp = updatedKeyData._5
    newKey
  }
}
