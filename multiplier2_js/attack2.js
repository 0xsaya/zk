web3 = require("web3")
snarkjs = require("snarkjs")
const fs = require("fs");
// const ZqField = require("./ffjavascript");

const { checkHash, proof, attackHashString } = Verfiy_exp()

async function Verfiy_exp() {
    // 初始化原始Proof
    let inputA = "7"
    let inputB = "11"
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({ a: inputA, b: inputB }, "Multiplier2.wasm", "multiplier2_0001.zkey")
    // console.log("Proof: ")
    // console.log(JSON.stringify(proof, null, 1));

    // 生成逆元
    const F = new ZqField(SNARK_FIELD_SIZE);
    const X = F.e("123456");
    const invX = F.inv(X);
    console.log("x:" ,X );
    console.log("invX" ,invX);
    return (checkHash, proof, attackHash)
}
async function verify(publicSignals, proof) {
    const vKey = JSON.parse(fs.readFileSync("verification_key.json"));
    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
    return 0
}


    // console.log("attackHashString" + attackHashString)

    // console.log("originalHash: " + originalHash + "\n")
    // console.log("attackHash: " + attackHash + "\n")
    // var attackHash2 = attackHash + q
    // console.log("attackHash2: " + attackHash2.toString() + "\n")
    // console.log("attackHash3: " + (attackHash + q + q).toString() + "\n")
    // console.log("attackHash4: " + (attackHash + q + q + q).toString() + "\n")