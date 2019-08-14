package bifrost.program

import java.util.UUID

import bifrost.transaction.box.{CodeBox, StateBox}
import bifrost.{BifrostGenerators, ValidGenerators}
import io.circe.JsonObject
import io.circe.syntax._
import org.graalvm.polyglot.Context
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}

class ProgramMethodSpec extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers
  with BifrostGenerators
  with ValidGenerators {

  property("Can call a function from a program") {
    forAll(programGen) {
      c: Program => {

        val party = propositionGen.sample.get
        val params = JsonObject.empty

        val prop = c.parties.head._1

        val state = c.executionBuilderObj.core.variables

        val stateTwo = s"""{ "b": 0 }""".asJson
        val stateThree = s"""{ "c": 0 }""".asJson

        val stateBox = StateBox(prop, 0L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 0L)), state)
        val stateBoxTwo = StateBox(prop, 1L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 1L)), stateTwo)
        val stateBoxThree = StateBox(prop, 2L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 2L)), stateThree)
        val codeBox = CodeBox(prop, 3L, UUID.nameUUIDFromBytes(CodeBox.idFromBox(prop, 3L)),
          Seq("function inc() { a += 1; return a; }"), Map("inc" -> Seq("Number", "Number")))

        val stateBoxUuids = Seq(
          (stateBox, UUID.nameUUIDFromBytes(stateBox.id)),
          (stateBoxTwo, UUID.nameUUIDFromBytes(stateBoxTwo.id)),
          (stateBoxThree, UUID.nameUUIDFromBytes(stateBoxThree.id))
        )

        val result = Program.execute(stateBoxUuids, Seq(codeBox), "inc")(party)(params)
        println(s"test result: $result")

        result.hcursor.get[Int]("a").right.get shouldEqual 1
      }
    }
  }

  property("Calling getFromState correctly reads from a read only StateBox") {
    forAll(programGen) {
      c: Program => {

        val prop = c.parties.head._1

        val state = c.executionBuilderObj.core.variables

        val stateTwo = s"""{ "b": 4 }""".asJson
        val stateThree = s"""{ "c": 7 }""".asJson

        val stateBox = StateBox(prop, 0L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 0L)), state)
        val stateBoxTwo = StateBox(prop, 1L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 1L)),stateTwo)
        val stateBoxThree = StateBox(prop, 2L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 2L)),stateThree)
        val codeBox = CodeBox(prop, 3L, UUID.nameUUIDFromBytes(CodeBox.idFromBox(prop, 3L)),Seq(
          "function changeState(uuid, value, state) { state = getFromState(uuid, value) }"
        ), Map("changeState" -> Seq("String", "String", "String")))

        val stateBoxUuids = Seq(
          (stateBox, UUID.nameUUIDFromBytes(stateBox.id)),
          (stateBoxTwo, UUID.nameUUIDFromBytes(stateBoxTwo.id)),
          (stateBoxThree, UUID.nameUUIDFromBytes(stateBoxThree.id))
        )

        val args = JsonObject.fromMap(Map(
            "uuid" -> s"_${stateBoxUuids.drop(1).head._2.toString.replace("-","_")}".asJson,
            "value" -> "b".asJson,
            "state" -> "a".asJson
          ))


        val mutableState = stateBoxUuids.head._1.state.asObject.get.toMap
        val programCode: String = Seq(codeBox).foldLeft("")((a,b) => a ++ b.code.foldLeft("")((a,b) => a ++ (b + "\n")))

        val jsre: Context = Context.create("js")
        val bindings = jsre.getBindings("js")

        //Pass in JSON objects for each read-only StateBox
        stateBoxUuids.tail.map{ sb =>
          val formattedUuid: String = "_" + sb._2.toString.replace("-", "_")
          jsre.eval("js", s"""var $formattedUuid = JSON.parse(${sb._1.state})""")
        }

        //Inject function to read from read only StateBoxes
        val getFromState =
          s"""
             |function getFromState(uuid, value) {
             |  return this[uuid][value]
             |}
       """.stripMargin

        jsre.eval("js", getFromState)

        //Pass in writable state and functions
        mutableState.foreach(s => bindings.putMember(s._1, s._2))
        jsre.eval("js", programCode)

        val preExecution: Map[String, String] = bindings.getMemberKeys.toArray.map(k => k.toString -> bindings.getMember(k.toString).toString).toMap
        println(s"preexecution: $preExecution")


        println(jsre.eval("js", s"""a = getFromState(${args("uuid").get}, ${args("value").get})"""))

        jsre.eval("js", s"""a = getFromState(${args("uuid").get}, ${args("value").get})""")

        //Return entire state of the evaluation
        val output: Map[String, String] = bindings.getMemberKeys.toArray.map(k => k.toString -> bindings.getMember(k.toString).toString).toMap
        //val output: Map[String, String] = mutableState.map(s => s._1 -> bindings.getMember(s._1).toString)

        println(s"output: $output")

        output("a").toInt shouldEqual 4

        //val result = Program.execute(stateBoxUuids, Seq(codeBox), "getFromState")(party)(params)
        //println(s"test result: $result")
      }
    }
  }

  property("Changing the type of a variable in a mutable StateBox will error") {
    forAll(programGen) {
      c: Program => {
        val program = c.executionBuilderObj.core.code.foldLeft("")((a,b) => a ++ (b + "\n"))
        val party = propositionGen.sample.get
        /*val params = JsonObject.fromMap(
          Map("newStatus" -> stringGen.sample.get.asJson))
         */
        val params = JsonObject.empty

        val prop = c.parties.head._1

        val state = c.executionBuilderObj.core.variables

        val stateTwo = s"""{ "b": 0 }""".asJson
        val stateThree = s"""{ "c": 0 }""".asJson

        val stateBox = StateBox(prop, 0L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 0L)), state)
        val stateBoxTwo = StateBox(prop, 1L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 1L)), stateTwo)
        val stateBoxThree = StateBox(prop, 2L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 2L)), stateThree)
        val codeBox = CodeBox(prop, 3L, UUID.nameUUIDFromBytes(CodeBox.idFromBox(prop, 3L)), Seq(
          s"""function changeType() {
             |  return a = "wrong"
             |}
           """.stripMargin), Map("changeType" -> Seq()))

        val stateBoxUuids = Seq(
          (stateBox, UUID.nameUUIDFromBytes(stateBox.id)),
          (stateBoxTwo, UUID.nameUUIDFromBytes(stateBoxTwo.id)),
          (stateBoxThree, UUID.nameUUIDFromBytes(stateBoxThree.id))
        )

        intercept[ClassCastException] {
          Program.execute(stateBoxUuids, Seq(codeBox), "changeType")(party)(params)
        }
      }
    }
  }

  property("Removing a mutable state variable during execution will result in an error") {
    forAll(programGen) {
      c: Program => {
        val program = c.executionBuilderObj.core.code.foldLeft("")((a,b) => a ++ (b + "\n"))
        val party = propositionGen.sample.get
        /*val params = JsonObject.fromMap(
          Map("newStatus" -> stringGen.sample.get.asJson))
         */
        val params = JsonObject.empty

        val prop = party

        val state = c.executionBuilderObj.core.variables

        val stateTwo = s"""{ "b": 0 }""".asJson
        val stateThree = s"""{ "c": 0 }""".asJson

        val stateBox = StateBox(prop, 0L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 0L)), state)
        val stateBoxTwo = StateBox(prop, 1L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 1L)), stateTwo)
        val stateBoxThree = StateBox(prop, 2L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 2L)), stateThree)
        val codeBox = CodeBox(prop, 3L, UUID.nameUUIDFromBytes(CodeBox.idFromBox(prop, 3L)), Seq(
          s"""function deleteVar() {
             |  delete global.a
             |}
           """.stripMargin), Map("deleteVar" -> Seq()))

        val stateBoxUuids = Seq(
          (stateBox, UUID.nameUUIDFromBytes(stateBox.id)),
          (stateBoxTwo, UUID.nameUUIDFromBytes(stateBoxTwo.id)),
          (stateBoxThree, UUID.nameUUIDFromBytes(stateBoxThree.id))
        )

        intercept[NullPointerException] {
          Program.execute(stateBoxUuids, Seq(codeBox), "deleteVar")(party)(params)
        }
      }
    }
  }

  property("Calling a function with mismatched argument types should fail") {
    forAll(programGen) {
      c: Program => {

        val party = propositionGen.sample.get

        val params = JsonObject.fromMap(Map("a" -> "2".asJson, "b" -> "2".asJson))

        val prop = c.parties.head._1

        val state = c.executionBuilderObj.core.variables
        println(s"state: ${state.toString}")

        val stateTwo = s"""{ "b": 0 }""".asJson
        val stateThree = s"""{ "c": 0 }""".asJson

        val stateBox = StateBox(prop, 0L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 0L)), state)
        val stateBoxTwo = StateBox(prop, 1L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 1L)), stateTwo)
        val stateBoxThree = StateBox(prop, 2L, UUID.nameUUIDFromBytes(StateBox.idFromBox(prop, 2L)), stateThree)
        val codeBox = CodeBox(prop, 3L, UUID.nameUUIDFromBytes(CodeBox.idFromBox(prop, 3L)), Seq(
          s"""add = function(a,b) {
             |  return a + b
             |}
           """.stripMargin), Map("add" -> Seq("Number", "Number")))

        val stateBoxUuids = Seq(
          (stateBox, UUID.nameUUIDFromBytes(stateBox.id)),
          (stateBoxTwo, UUID.nameUUIDFromBytes(stateBoxTwo.id)),
          (stateBoxThree, UUID.nameUUIDFromBytes(stateBoxThree.id))
        )

        intercept[Exception] {
          Program.execute(stateBoxUuids, Seq(codeBox), "add")(party)(params)
        }
      }
    }
  }

  /*property("Can call createAssets protocol level function from a program") {
    forAll(programGen) {
      c: Program => {
        val party = propositionGen.sample.get
        val params = JsonObject.fromMap(
          Map(
            "issuer" -> stringGen.sample.get.asJson,
            "to" -> stringGen.sample.get.asJson,
            "assetCode" -> stringGen.sample.get.asJson,
            "amount" -> positiveTinyIntGen.sample.get.asJson))

        println(s"createAssets params: ${params}")

        val result = Program.execute(c, "createAssets")(party)(params)
        println(s"test result: $result")
        assert(result.isSuccess)
      }
    }
  }*/

  /*property("Can call transferAssets protocol level function from a program") {
    forAll(programGen) {
      c: Program => {
        val party = propositionGen.sample.get
        val params = JsonObject.fromMap(
          Map(
            "amount" -> positiveTinyIntGen.sample.get.asJson,
            "recipient" -> stringGen.sample.get.asJson,
            "issuer" -> stringGen.sample.get.asJson,
            "asset" -> stringGen.sample.get.asJson,
            "data" -> stringGen.sample.get.asJson))

        val result = Program.execute(c, "transferAssets")(party)(params)
        println(result)
        assert(result.isSuccess)
      }
    }
  }*/

  /*property("Can call polyTransfer protocol level function from a program") {
    forAll(programGen) {
      c: Program => {
        val party = propositionGen.sample.get
        val params = JsonObject.fromMap(
          Map(
            "publicKey" -> stringGen.sample.get.asJson,
            "amount" -> positiveTinyIntGen.sample.get.asJson))

        val result = Program.execute(c, "transferPolys")(party)(params)
        println(result)
        assert(result.isSuccess)
      }
    }
  }*/

    /*val name: String = "assetCreation"
    val assetCode: String = "Wheat"
    val effectiveTimestamp = Instant.now.toEpochMilli
    val expirationTimestamp = Instant.now.toEpochMilli + 10000L
    val program: String =
      s
         |this.$name = function(){
         |    this.programEffectiveTime = $effectiveTimestamp;
         |    this.programExpirationTime = $expirationTimestamp;
         |    this.status = "initialized"
         |    this.assetCode = "$assetCode"
         |    this.initialCapital = "0";
         |
         |    this.changeStatus = function(newStatus) {
         |      this.status = newStatus;
         |      return this;
         |    }
         |
         |    this.newAsset = function(asset, amount) {
         |      createAsset(asset, amount);
         |      return this;
         |    }
         |}
         |
         |this.$name.fromJSON = function(str) {
         |    return new $name();
         |}
         |
         |this.$name.toJSON = function(o) {
         |    return JSON.stringify(o);
         |}
     """.stripMargin

    var state = "{}".asJson

    val polyglot: Context = Context.create()

    val protocolStateListener: Value = polyglot.eval("js",
      s"""
         |function protocolStateListener() {
         |
       """.stripMargin)

    val createAsset: Value = polyglot.eval("js",
      s"""
         |async function createAsset() {
         |    await
       """.stripMargin)



    val party = propositionGen.sample.get
    val params = JsonObject.fromMap(Map("asset" -> stringGen.sample.get.asJson, "amount" -> positiveTinyIntGen.sample.get.asJson))

    val result = Program.execute(program, "createAsset")(party)(params)
    println(s">>>>>>>> Result: $result")*/
}